---
title: Solución de problemas
description: Problemas frecuentes y cómo resolverlos — PATH, la lista permitida, el fallback de biometría y el prompt del keychain.
---

## Inyección de `high`/`prod` rechazada — "not on the executor allowlist"

Un valor `high` o `prod` solo puede inyectarse en un ejecutable **revisado y
en la lista permitida**. Agrégalo en la ejecución con `--allow`:

```bash
kovra run --env prod --allow./deploy --./deploy
```

Esto es independiente del prompt de <span class="bioprove">bioProve</span> — gobierna *hacia dónde* puede ir el
valor, no *si se te solicitó*. Consulta [el proceso de decisión](/es/security/decision/).

## El prompt de <span class="bioprove">bioProve</span> nunca aparece

En un host sin biometría (sin hardware, sin enrolamiento, o una sesión headless/CI),
kovra cae al **broker de archivos**. El comando espera e imprime instrucciones;
apruébalo desde otra terminal:

```bash
kovra approve --list
kovra approve <id>
```

Puedes forzar el canal con `KOVRA_CONFIRMER=biometric|file`.

## macOS solicita la contraseña de inicio de sesión en cada ejecución

Si un `kovra` recién compilado sigue pidiendo la contraseña del **keychain de inicio
de sesión** para leer la clave maestra, otorga acceso permanente al binario: en
**Keychain Access**, busca el ítem `kovra` / `master-key` y, en **Access Control**,
permite la aplicación `kovra` (o "Allow all applications"). Esto ocurre porque un
binario firmado ad-hoc obtiene una nueva identidad de código en cada compilación; una
compilación firmada con certificado de release es estable.

Alternativamente, ejecuta en **modo passphrase** (sin keychain en absoluto) definiendo
`KOVRA_PASSPHRASE` — kovra derivará entonces la clave con Argon2 desde tu passphrase
y una sal almacenada.

## `command not found: kovra` (o `kovra-mcp`)

El binario no está en tu `PATH`. Tras una instalación con Homebrew debería ser
automático; desde el código fuente, cópialo: `cp target/release/kovra /usr/local/bin/`. Para `kovra-mcp`,
verifica con `which kovra-mcp` — y recuerda que es un **servidor MCP stdio** que
lanza tu agente, no algo que ejecutes manualmente.

## El agente no ve las herramientas de kovra

Después de `kovra setup`, **recarga tu agente** para que vuelva a leer `.mcp.json`.
Confirma que el servidor está registrado allí y que `kovra-mcp` está en tu `PATH`.
El agente solo ve metadatos con alcance definido — si una coordenada está fuera de su
[alcance](/es/concepts/agent-scope/), es *inaccesible*, por diseño.

## Un secreto no se puede revelar

Los secretos `inject-only` **nunca** se revelan — solo pueden inyectarse. Los secretos
`high` y `prod` nunca se revelan a un agente, y se revelan desde la CLI solo después
de un <span class="bioprove">bioProve</span>. Esta es la política funcionando según lo previsto, no un error; consulta
[Niveles de sensibilidad](/es/concepts/sensitivity/).
