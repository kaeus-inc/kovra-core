---
title: Criptografía
description: Cada algoritmo criptográfico que usa kovra, los parámetros exactos, la biblioteca detrás de cada uno y por qué se tomó cada decisión.
---

kovra **no implementa criptografía propia**. Cada primitiva a continuación es una implementación Rust verificada y ampliamente utilizada — la familia [RustCrypto](https://github.com/RustCrypto), [`age`](https://age-encryption.org/), y [BLAKE3](https://github.com/BLAKE3-team/BLAKE3). El trabajo de kovra es *componerlas* correctamente: la primitiva adecuada para cada tarea, los parámetros correctos, y sin texto plano donde no debería estar.

Esta página documenta exactamente lo que se ejecuta, con los parámetros reales del código fuente.

## De un vistazo

| Propósito | Algoritmo | Clave / parámetros | Biblioteca |
| --- | --- | --- | --- |
| Cifrado en reposo | ChaCha20-Poly1305 (AEAD) | Clave de 256 bits, nonce aleatorio de 96 bits por escritura | `chacha20poly1305` |
| Custodia de clave maestra | Keyring del SO | — (Keychain / Credential Manager / Secret Service) | `keyring` |
| Derivación de clave sin interfaz | Argon2id | 19 MiB de memoria, 2 pasadas, 1 carril → clave de 256 bits | `argon2` |
| Huella digital de valor | BLAKE3 (truncado) | primeros 4 bytes → 8 caracteres hex | `blake3` |
| Direccionamiento de coordenadas | BLAKE3 | resumen completo de la ruta canónica | `blake3` |
| Compartición / paquetes sellados | `age` (X25519 + ChaCha20-Poly1305) | sellado a la clave pública del destinatario | `age`, `ssh-key` |
| Copia de seguridad de clave maestra | `age` scrypt (passphrase) | codificación ASCII | `age` |
| Pares de claves de firma | ed25519 / RSA-3072 (PKCS#1 v1.5 + SHA-2) | formato OpenSSH | `ssh-key`, `rsa` |
| Cifrado asimétrico | X25519 (vía `age`, solo claves ed25519) | — | `age`, `ssh-key` |
| Códigos TOTP | RFC-6238 HMAC-SHA1 (SHA-256/512 opcionales) | 6 dígitos, período de 30 segundos | `hmac`, `sha1`/`sha2` |
| Aleatoriedad | CSPRNG del SO | — | `getrandom` / `OsRng` |
| Higiene en memoria | zeroize + secrecy | — | `zeroize`, `secrecy` |

## Cifrado en reposo

Cada registro del vault — y el índice de metadatos — está sellado de manera independiente con **ChaCha20-Poly1305**, un cifrado AEAD (cifrado autenticado con datos asociados), bajo la **clave maestra de 256 bits** del vault. Cada escritura genera un **nonce aleatorio fresco de 96 bits**, por lo que dos sellos del mismo registro siempre difieren y un nonce nunca se reutiliza. Los metadatos y el valor están sellados **juntos**, por lo que ni el secreto ni su coordenada aparecen como texto plano en disco. La etiqueta de autenticación (Poly1305) significa que un registro manipulado falla al abrirse en lugar de devolver basura, y los fallos de descifrado son **opacos** — una clave incorrecta, un texto cifrado corrupto y un nonce mal formado son indistinguibles, por lo que el error no puede actuar como un oráculo. El buffer temporal de texto plano se zeroiza tras su uso.

**Por qué ChaCha20-Poly1305.** Es un AEAD moderno de tiempo constante que es rápido en software puro sin instrucciones especiales de CPU (a diferencia de AES, que se apoya en AES-NI tanto para velocidad como para resistencia a side channels) — el valor predeterminado correcto para una herramienta que se ejecuta en cualquier portátil que tengas. AEAD proporciona confidencialidad *e* integridad en un solo paso, y el nonce aleatorio por registro evita el modo de fallo catastrófico de la reutilización de nonce.

## Custodia de la clave maestra

La clave maestra de 256 bits nunca se escribe, muestra ni incluye en un archivo de proyecto. Por defecto vive en el **keyring del SO** — el Keychain de macOS, el Administrador de credenciales de Windows o el Secret Service de Linux — y kovra la carga solo para sellar y abrir registros.

Para uso sin interfaz (CI, contenedores, sin keyring), kovra deriva la clave en su lugar con **Argon2id**, el KDF de contraseñas resistente a memoria, a partir de una passphrase más una sal estable por vault. Se ejecuta con los valores predeterminados de la biblioteca — **19 MiB de memoria, 2 pasadas, 1 carril** — produciendo la clave de 256 bits de manera determinista, por lo que el mismo vault se abre en múltiples ejecuciones sin necesidad de almacenar nada secreto en disco (solo la sal no secreta).

**Por qué Argon2id.** La resistencia a memoria hace que la fuerza bruta de una passphrase robada sea costosa en GPUs y hardware especializado; Argon2id es el estándar actual (y el ganador de la Competición de Hashing de Contraseñas). El keyring del SO es preferido cuando está disponible porque vincula la clave a la sesión de inicio de sesión del usuario y las protecciones propias de la plataforma; Argon2id es la alternativa portátil que no necesita nada más que una passphrase.

## Hashing y huellas digitales

kovra usa **BLAKE3** en dos lugares:

- **Huellas digitales de valores.** `kovra list` y `doctor` muestran una huella digital **truncada** — los primeros **4 bytes** del resumen BLAKE3, como 8 caracteres hex en minúsculas. Es determinista (sin sal), por lo que puedes responder "¿cambió este valor?" o "¿es este el mismo secreto que antes?" sin ver jamás el valor. Es deliberadamente demasiado corta para ayudar a forzar el valor por fuerza bruta, y **nunca** es el hash completo.
- **Direccionamiento de coordenadas.** El identificador en disco de un registro es el resumen BLAKE3 de su ruta canónica `env/componente/clave`, por lo que las coordenadas no se exponen como nombres de archivo en texto plano.

**Por qué BLAKE3.** Es rápido, moderno y tiene una API limpia que es difícil de usar mal. La seguridad de la huella digital proviene del *truncamiento más el determinismo*: suficientemente larga para detectar un cambio, suficientemente corta como para que revele esencialmente nada sobre el valor.

## Compartición — paquetes sellados

Un [paquete sellado](/es/guides/sharing/) es una caja **`age`**. `age` usa acuerdo de clave **X25519** con **ChaCha20-Poly1305** para el payload; kovra sella la clave pública **ed25519** del destinatario a través de la ruta de destinatario SSH de `age`. Solo el titular de la clave privada correspondiente puede abrirlo — la posesión del archivo no es autorización.

La entrega desatendida de entradas sensibles añade un **segundo factor** sin una segunda clave: el paquete embebe un **compromiso** `BLAKE3(token_secret)` dentro del payload sellado, y el **token de acceso** entregado por separado es la preimagen. Una apertura desatendida, por tanto, necesita *tanto* la identidad del destinatario (para descifrar y leer el compromiso) *como* el token fuera de banda (para satisfacerlo). Los secretos de producción son rechazados en el momento del sellado y verificados de nuevo al abrir.

**Límite honesto.** Un paquete es **solo confidencialidad**. La etiqueta AEAD de `age` garantiza la integridad — un paquete manipulado no se abrirá — pero el formato **no lleva firma**, por lo que demuestra *quién puede leerlo*, no *quién lo escribió*. Si necesitas autenticidad del remitente, firma el payload con un [par de claves](/es/guides/keypairs/) fuera de banda.

## Copia de seguridad de la clave maestra

`kovra key export` escribe una copia de seguridad de recuperación ante desastres de la clave maestra como un blob **`age` scrypt con codificación ASCII** — cifrado bajo una passphrase de recuperación que tú eliges, descifrable por cualquier implementación de `age` en una emergencia. El texto plano transitorio se borra tras la llamada; solo el blob cifrado se devuelve.

## Pares de claves y firma

Los [pares de claves](/es/guides/keypairs/) custodiados se almacenan en formato **OpenSSH** y se usan solo *a través* de kovra:

- **ed25519** — firma (curva Edwards) **y** cifrado asimétrico (X25519, mediante la ruta `age` descrita arriba).
- **RSA-3072** — firma y SSH únicamente, usando **PKCS#1 v1.5 con SHA-2**. Deliberadamente **sin cifrado RSA** — cuando necesitas cifrar para una clave, usa ed25519.

Las firmas se realizan bajo un namespace de firma SSH fijo, por lo que una firma producida por kovra se verifica con el estándar `ssh-keygen -Y verify`. La mitad privada se genera dentro del vault, sellada bajo la clave maestra con la misma ruta ChaCha20-Poly1305 que cualquier otro secreto, y **nunca se escribe en disco ni se imprime**.

**Por qué ed25519 primero.** Claves pequeñas, firmas rápidas, sin errores de parámetros, y un puente limpio al cifrado mediante X25519. RSA-3072 (≈128 bits de seguridad) se mantiene para interoperabilidad con sistemas que aún requieren RSA.

## TOTP

Un [registro TOTP](/es/guides/totp/) custodia la semilla compartida y calcula códigos según **RFC-6238**: **HMAC-SHA1** por defecto (el valor predeterminado del RFC), con **SHA-256** y **SHA-512** disponibles, **6 dígitos**, período de **30 segundos**. El HMAC se construye sobre los crates `hmac` + `sha1`/`sha2`. La **semilla está sellada como cualquier otro secreto y nunca se revela** — solo se produce el código derivado y limitado en tiempo.

## Aleatoriedad

Todos los nonces, los secretos generados (`kovra generate`) y los pares de claves recién creados se obtienen del **CSPRNG del sistema operativo** (`getrandom` / `OsRng`) — nunca de un PRNG en espacio de usuario sembrado desde una fuente predecible.

## Higiene en memoria

Los tipos que contienen secretos están envueltos en `secrecy` e implementan `zeroize`: su `Debug`/`Display` está redactado (un valor no puede filtrarse en una línea de log o un mensaje de pánico), y los bytes subyacentes se **limpian de la memoria** al liberarse. Los buffers temporales de texto plano — el registro descifrado, el payload serializado antes del sellado — se zeroizan explícitamente tan pronto como ya no son necesarios.

## Lo que kovra deliberadamente *no* hace

- **Sin criptografía propia.** Cada primitiva es una biblioteca verificada y ampliamente revisada; kovra solo las compone.
- **Sin reutilización de nonce.** Cada sello AEAD usa un nonce aleatorio fresco.
- **Sin oráculo de valores.** Las huellas digitales están truncadas y los errores son opacos.
- **Sin autenticación del remitente en paquetes.** Los paquetes sellados son solo confidencialidad; agrega una firma si necesitas demostrar la autoría.
- **Sin protección más allá de la entrega.** Una vez que un valor se entrega al proceso que lo necesita, vive en la memoria de ese proceso bajo las reglas de ese programa — la criptografía de kovra asegura la custodia y la entrega, no lo que un programa hace con un valor después de recibirlo.
