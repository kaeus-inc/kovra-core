# kovra-wrapper

The subprocess **wrapper** for [kovra](https://kovra.sh) — it launches a child
process with resolved secrets placed into its **environment**, and nowhere else.

Secrets reach the child through the environment block only:

- never on the command line (no secret value is ever placed in argv);
- never written to disk by the wrapper;
- never logged or printed.

Secret-bearing values are held in zeroizing buffers for the brief window between
resolution and handing them to the child, and the wrapper observes the parent
process so an attended-confirmation prompt can name the requesting command
honestly.

Part of the kovra workspace: <https://github.com/kaeus-inc/kovra-core>.
Licensed under BUSL-1.1.
