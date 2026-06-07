---
title: El proceso de decisión
description: Cómo kovra decide qué sucede con un secreto en cada solicitud — alcance, operación, sensibilidad, entorno y origen — explicado en detalle.
---

Cada solicitud para tocar un secreto — ya sea que provenga de ti en la terminal, desde la interfaz web o desde un agente de IA — pasa por **una decisión**. Esa decisión se toma en un solo lugar y es la misma para cada canal; ninguna interfaz puede inventar sus propias reglas. Esta página recorre esa decisión en detalle, pero de manera conceptual — *qué* se evalúa y *en qué orden*, no cómo está codificado.

[La descripción general de "cómo funciona"](/es/concepts/how-it-works/) muestra los flujos cotidianos; esta es la verificación que subyace a todos ellos.

## Los cuatro resultados posibles

Cada solicitud se resuelve en exactamente uno de estos:

- **Permitir** — proceder, sin aviso.
- **Confirmar y luego permitir** — proceder solo después de un <span class="bioprove">bioProve</span>.
- **Denegar** — rechazado, con una razón registrada para auditoría (nunca el valor).
- **No direccionable** — el secreto no existe *para este canal*. Esto no es una denegación después del hecho; la solicitud nunca resuelve a un secreto real.

## El orden de evaluación

El orden importa, porque las verificaciones más baratas y más sólidas vienen primero.

### 1. ¿Está siquiera en el alcance?

Antes que nada, kovra pregunta: ¿está esta coordenada, y esta operación, *dentro del [alcance](/es/concepts/agent-scope/) del canal que pregunta?* Si no, la respuesta es **no direccionable** — el secreto nunca se muestra, nunca se resuelve, nunca "casi se entrega." Esto es defensa en profundidad deliberada: un canal no puede ser engañado para filtrar algo a lo que nunca tuvo acceso, porque para ese canal el secreto simplemente no existe. Un agente que ha sido manipulado aún no puede solicitar lo que su alcance excluye.

### 2. ¿Qué tipo de operación es esta?

Hay tres cosas que puedes hacer con un secreto, y conllevan riesgos muy diferentes:

- **Leer metadatos** — listarlo, verificar su estado, ver su huella digital. Nunca se toca ningún valor, por lo que si es direccionable, está permitido.
- **Inyectar** — enviar el valor *a través* de una operación hacia un proceso que lo necesita. El valor fluye; nunca regresa al llamador.
- **Revelar** — traer el texto plano *de vuelta a las manos del llamador*. Este es el único camino donde un valor llega a algún lugar que un humano o un modelo puede leer, por lo que es el más protegido.

### 3. Para una revelación — ¿quién pregunta y cuán sensible es?

Las revelaciones se juzgan según cuatro factores en conjunto: la **sensibilidad** del secreto, su **entorno**, el **canal** que pregunta y el **origen** (un humano actuando deliberadamente, o un agente). Las reglas, en términos simples:

- Los secretos más protegidos (**inject-only**) **nunca se revelan** — a nadie, en ningún canal. Solo pueden inyectarse.
- El **canal del agente nunca recibe** el texto plano de un secreto `high`, `prod` o `inject-only`. Lo único que puede leer de vuelta es un secreto ordinario, no de producción, que hayas **marcado explícitamente como revelable** — y nada más.
- La **interfaz web nunca muestra** el texto plano de los secretos más sensibles; los muestra enmascarados, con solo metadatos.
- El **texto plano de producción** solo puede llegar al contexto de un agente a través de una revelación que un *humano* inicia a propósito, confirmada con biometría — nunca una que un agente pueda iniciar, y nunca por defecto.
- Una revelación ordinaria en tu propia terminal procede; una de sensibilidad **high** primero te pide que hagas <span class="bioprove">bioProve</span>.

### 4. Para una inyección — ¿necesita tu confirmación?

La inyección es más segura que revelar, porque el valor pasa a un proceso en lugar de regresar al llamador. Si se pausa para una confirmación depende **únicamente de la sensibilidad**: un secreto `high` solicita un <span class="bioprove">bioProve</span> antes de inyectarse; los secretos ordinarios (y los `inject-only`, cuya *única* forma de entrega es la inyección) fluyen sin aviso. El entorno no cambia esta parte.

### 5. Para una inyección de nivel alto o producción — ¿a dónde se le permite ir?

Hay una segunda guarda independiente sobre las inyecciones más riesgosas. Enviar un valor `high` o `prod` a un programa que el propio agente escribió anularía el propósito — ese programa podría simplemente imprimir el valor de vuelta. Por eso esas inyecciones solo están permitidas hacia un **ejecutable que ha sido revisado y está en la lista de permitidos**. Esto es independiente del aviso de confirmación: trata sobre *adónde* puede ir el valor, no sobre *si se te preguntó*. Un secreto de producción deliberadamente degradado puede por tanto inyectarse sin aviso, pero aun así solo hacia un programa en la lista de permitidos.

### 6. Cuando se necesita una confirmación, el aviso no puede falsificarse

Si la decisión es "confirmar primero," el texto que ves es construido por kovra mismo a partir de los **hechos reales** de la solicitud — el comando exacto, la coordenada, la sensibilidad — y nunca a partir de quien hizo la solicitud. Un atacante (o un agente manipulado) no puede presentarte un aviso de aspecto tranquilizador que oculte lo que realmente estás aprobando. Cualquier descripción de formato libre proporcionada por un llamador se mantiene separada y claramente marcada como no confiable.

### 7. Todo queda registrado

Sea cual sea el resultado, kovra lo escribe en el rastro de auditoría: la acción, la coordenada, el resultado y quién lo inició. El rastro **nunca contiene un valor secreto**, y nunca una huella digital suficientemente completa como para confirmar una suposición. Puedes ver lo que sucedió sin que ninguna parte de eso se convierta en un nuevo lugar donde un secreto podría filtrarse.

## Unificando todo — algunos recorridos

- **Un agente ejecuta tu suite de pruebas, que necesita una contraseña de base de datos `dev`.** ¿En el alcance? Sí. ¿Operación? Inyectar. ¿Sensibilidad? Ordinaria. → **Permitido**, sin aviso; el valor fluye hacia el proceso de prueba, nunca al contexto del agente.
- **Un agente solicita leer una clave API `prod`.** ¿Operación? Revelar. ¿Canal? Agente. → **Denegado** — el texto plano de producción nunca entra al contexto de un agente, punto.
- **Tú solicitas, en tu terminal, inyectar un secreto `prod` en tu herramienta de despliegue.** La sensibilidad es `high` (producción nace como `high`), por lo que kovra **te pide que confirmes**; y porque es producción, la herramienta de despliegue debe ser un ejecutable **en la lista de permitidos**. Confirmado y en la lista → se ejecuta.
- **Un agente lista los secretos de un proyecto que no tiene en su alcance.** → **No direccionable** — esos secretos no existen para esa sesión en absoluto.
