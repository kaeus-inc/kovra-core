---
title: Cómo funciona
description: Los flujos principales de kovra, de extremo a extremo y a alto nivel — almacenar, usar, delegar a un agente, revelar y compartir un secreto.
---

kovra tiene solo un puñado de flujos. Esta página recorre cada uno **a alto nivel** — qué sucede, conceptualmente, sin entrar en los internos. Para el relato detallado de cómo se *decide* una solicitud, consulta [El proceso de decisión](/es/security/decision/) en el modelo de seguridad.

## Almacenar un secreto

Le entregas a kovra un valor una sola vez. Sella el valor en el [vault](/es/concepts/vault/) y recuerda únicamente sus [metadatos](/es/concepts/coordinates/) — la coordenada, la [sensibilidad](/es/concepts/sensitivity/), una descripción opcional. A partir de ese momento el valor nunca se te imprime como efecto secundario del trabajo cotidiano; vive cifrado y solo se *entrega*, nunca se *muestra*.

## Usar un secreto en un proceso

Este es el camino cotidiano. Describes el cableado una vez en un archivo [`.env.refs`](/es/concepts/env-refs/) — nombres de variables mapeados a coordenadas, direcciones sin valores — y luego le pides a kovra que ejecute tu comando. Conceptualmente:

1. Ejecutas tu herramienta *a través de* kovra.
2. kovra lee el cableado y busca cada dirección.
3. Verifica la política para cada valor (¿está permitido, en este canal, con esta sensibilidad?).
4. Entrega los valores resueltos **directamente al proceso de tu comando** y lo inicia.

El comando trabaja con los valores reales; nada se escribió en un archivo, nada apareció en pantalla ni quedó en el historial de tu shell. El secreto fue *usado*, no *visto*.

## Permitir que un agente use un secreto

Cuando hay un agente de IA involucrado, la misma idea aplica con un límite añadido. El agente se conecta bajo un [alcance](/es/concepts/agent-scope/) — una declaración de lo que esta sesión puede direccionar y hacer. Conceptualmente:

1. El agente ve **metadatos** — que existe un secreto, su nombre y sensibilidad — y razona sobre tu proyecto.
2. Cuando necesita un secreto para ejecutar algo realmente, kovra **inyecta** el valor en ese comando, igual que arriba.
3. El **plaintext sensible nunca entra en el contexto del agente** — puede usar el secreto sin haberlo leído nunca.

## Revelar un secreto para ti mismo

A veces *tú* genuinamente necesitas ver un valor. Lo solicitas explícitamente, y kovra trata eso como el camino vigilado:

1. Solicitas una coordenada específica.
2. kovra verifica su sensibilidad. Para un secreto ordinario lo muestra; para uno sensible primero te pide <span class="bioprove">bioProve</span>.
3. Los secretos más protegidos nunca se muestran — solo pueden inyectarse.

Revelar es siempre un acto deliberado y atendido — nunca algo que ocurre solo, y nunca algo que un agente puede desencadenar por ti.

## Compartir un secreto con otra persona

Para entregar un conjunto de secretos a otra persona o máquina, kovra los **sella** con la llave pública del destinatario como un paquete portable (o, para una máquina nueva, un kit USB que arranca todo). Conceptualmente:

1. Eliges un entorno que no sea producción para compartir.
2. kovra sella esos valores de modo que **solo el destinatario previsto** pueda abrirlos, e imprime por separado un token de acceso de un solo uso para entregar por otro canal.
3. El destinatario abre el paquete **con su propia identidad**; los secretos de producción nunca son compartibles de esta manera.

La autorización está anclada a *quién es el destinatario*, no a quien tenga el archivo.

---

Cada uno de estos flujos ejecuta la misma verificación subyacente antes de que un valor se mueva. Esa verificación — y exactamente cómo decide — es el tema de [el modelo de seguridad](/es/security/decision/).
