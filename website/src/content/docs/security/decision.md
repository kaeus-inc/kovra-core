---
title: The decision process
description: How kovra decides what happens to a secret on every request — scope, operation, sensitivity, environment, and origin — walked through in detail.
---

Every request to touch a secret — whether it comes from you at the terminal, from
the Web UI, or from an AI agent — passes through **one decision**. That decision is
made in a single place and is the same for every channel; no interface gets to
invent its own rules. This page walks through that decision in detail, but
conceptually — *what* is weighed and *in what order*, not how it's coded.

[The "how it works" overview](/concepts/how-it-works/) shows the everyday flows;
this is the check that sits underneath all of them.

## The four possible outcomes

Every request resolves to exactly one of these:

- **Allow** — proceed, no prompt.
- **Confirm, then allow** — proceed only after a <span class="bioprove">bioProve</span>.
- **Deny** — refused, with a reason recorded for audit (never the value).
- **Unaddressable** — the secret does not exist *for this channel*. This is not a
 denial after the fact; the request never even resolves to a real secret.

## The order of evaluation

The order matters, because the cheapest and strongest checks come first.

### 1. Is it even in scope?

Before anything else, kovra asks: is this coordinate, and this operation, *within
the asking channel's [scope](/concepts/agent-scope/)?* If not, the answer is
**unaddressable** — the secret is never surfaced, never resolved, never "almost
delivered." This is deliberate defense in depth: a channel can't be tricked into
leaking something it was never allowed to reach, because for that channel the
secret simply doesn't exist. An agent that has been manipulated still can't ask for
what its scope excludes.

### 2. What kind of operation is this?

There are three things you can do with a secret, and they carry very different
risk:

- **Read metadata** — list it, check its status, see its fingerprint. No value is
 ever touched, so if it's addressable, it's allowed.
- **Inject** — send the value *through* an operation into a process that needs it.
 The value flows through; it never comes back to the caller.
- **Reveal** — bring the plaintext *back into the caller's hands*. This is the one
 path where a value lands somewhere a human or a model can read it, so it's the
 most guarded.

### 3. For a reveal — who's asking, and how sensitive is it?

Reveals are judged on four things together: the secret's **sensitivity**, its
**environment**, the **channel** asking, and the **origin** (a human acting
deliberately, or an agent). The rules, in plain terms:

- The most protected secrets (**inject-only**) are **never revealed** — to anyone,
 on any channel. They can only be injected.
- The **agent channel never receives** the plaintext of a `high`, a `prod`, or an
 inject-only secret. The only thing it can ever read back is an ordinary,
 non-production secret that you have **explicitly marked as revealable** — and
 nothing else.
- The **Web UI never displays** the plaintext of the most sensitive secrets; it
 shows them masked, with metadata only.
- **Production plaintext** can reach an agent's context **only** through a reveal a
 *human* starts on purpose, confirmed with biometrics — never one an agent can
 initiate, and never by default.
- An ordinary reveal at your own terminal proceeds; a **high**-sensitivity one
 first asks you to <span class="bioprove">bioProve</span>.

### 4. For an injection — does it need your confirmation?

Injection is safer than revealing, because the value passes through to a process
rather than back to the caller. Whether it pauses for a confirmation depends on
**sensitivity alone**: a `high` secret asks for a <span class="bioprove">bioProve</span>
before it's injected; ordinary secrets (and inject-only, whose *only* delivery is
injection) flow through without a prompt. The environment doesn't change this part.

### 5. For a high or production injection — where is it allowed to go?

There's a second, independent guard on the riskiest injections. Sending a `high`
or `prod` value into a program the agent itself wrote would defeat the point — that
program could simply print the value back. So those injections are only allowed
into an **executable that has been reviewed and allowlisted**. This is separate
from the confirmation prompt: it's about *where* the value may go, not *whether you
were asked*. A deliberately down-graded production secret can therefore inject
without a prompt, yet still only into an allowlisted program.

### 6. When a confirmation is needed, the prompt can't be faked

If the decision is "confirm first," the text you see is built by kovra itself from
the **real facts** of the request — the exact command, the coordinate, the
sensitivity — and never from whoever made the request. An attacker (or a
manipulated agent) can't hand you a reassuring-looking prompt that hides what
you're actually approving. Any free-form description supplied by a caller is kept
separate and clearly marked as untrusted.

### 7. Everything is recorded

Whatever the outcome, kovra writes it to the audit trail: the action, the
coordinate, the result, and who initiated it. The trail **never contains a secret
value**, and never a fingerprint complete enough to confirm a guess. You can see
what happened without any of it becoming a new place a secret could leak.

## Putting it together — a few walkthroughs

- **An agent runs your test suite, which needs a `dev` database password.** In
 scope? Yes. Operation? Inject. Sensitivity? Ordinary. → **Allowed**, no prompt;
 the value flows into the test process, never into the agent's context.
- **An agent asks to read a `prod` API key.** Operation? Reveal. Channel? Agent. →
 **Denied** — production plaintext never enters an agent's context, full stop.
- **You ask, at your terminal, to inject a `prod` secret into your deploy tool.**
 Sensitivity is `high` (production is born high), so kovra **asks you to
 confirm**; and because it's production, the deploy tool must be an **allowlisted**
 executable. Confirmed and allowlisted → it runs.
- **An agent lists the secrets in a project it doesn't have in scope.** →
 **Unaddressable** — those secrets don't exist for that session at all.
