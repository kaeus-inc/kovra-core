---
title: Contribuir
description: Cómo contribuir a kovra.
---

Las contribuciones son bienvenidas — reportes de errores, ideas, documentación y código. kovra es
una herramienta de seguridad, por lo que algunas reglas básicas tienen más peso del habitual.

## Reglas básicas

- **Nunca incluyas un secreto real.** Ni en código, pruebas, issues, capturas de pantalla ni
  en discusiones. Todas las pruebas usan valores descartables y mocks — la herramienta que
  protege secretos no debe ingerir ninguno.
- **Reporta problemas de seguridad de forma privada.** No abras un issue público para una
  vulnerabilidad — consulta [Soporte y comunidad](/es/project/support/) para saber cómo hacerlo.
- **Mantén intacto el perímetro de seguridad.** Los invariantes de kovra son deliberados; un
  cambio que debilite uno para facilitar una funcionalidad no será aceptado. Si una tarea parece
  requerirlo, plantéalo para discusión antes de proceder.

## Reportar un error o proponer un cambio

1. Busca primero en el [rastreador de issues](https://github.com/kaeus-inc/kovra-core/issues).
2. Abre un issue describiendo el comportamiento (pasos, resultado esperado vs. resultado real)
   o la idea.
3. Para código, abre un pull request contra
   [`kaeus-inc/kovra-core`](https://github.com/kaeus-inc/kovra-core). Mantén el cambio enfocado
   y explica el *porqué*.

## Trabajar en el código

kovra es Rust (core/CLI/wrapper/Web UI) con un servidor MCP en Python. Antes de abrir un
PR, asegúrate de que el gate estándar esté en verde:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

El comportamiento nuevo debe incluir pruebas — y el comportamiento relevante para la seguridad
debe incluir una prueba que fije la garantía que proporciona.
