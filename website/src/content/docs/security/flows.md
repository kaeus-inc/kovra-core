---
title: Flows
description: The different flows kovra supports — process injection, agent use over MCP, human reveal, sealed sharing, USB exchange, ssh-agent, and the Web UI — each with a diagram.
---

kovra moves a secret in a few distinct ways. Each **flow** below is one scenario,
with a diagram showing the path the value takes — and, just as importantly, where
it is **not** allowed to go. They all run through the same underlying check; see
[the decision process](/security/decision/) for how that check works.

<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<marker id="fd-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#46586d"/></marker>
<marker id="fd-av" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#34d399"/></marker>
<marker id="fd-an" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#fb7185"/></marker>
<marker id="fd-at" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d4af37"/></marker>
</defs></svg>

## Process injection

The everyday flow. You wire variable names to coordinates in `.env.refs`, run your
tool *through* kovra, and the resolved values go **straight into the process** —
never to disk, argv, or your screen. The value is used, not seen.

<figure class="flow-diagram">
<svg viewBox="0 0 680 150" role="img" aria-label="Process injection flow">
  <rect class="box" x="34" y="51" width="150" height="54" rx="8"/>
  <text class="t" x="109" y="75" text-anchor="middle">.env.refs</text>
  <text class="s" x="109" y="92" text-anchor="middle">addresses, no values</text>

  <rect class="box core" x="265" y="45" width="150" height="66" rx="8"/>
  <text class="t" x="340" y="73" text-anchor="middle">kovra</text>
  <text class="s" x="340" y="93" text-anchor="middle">policy · vault</text>

  <rect class="box" x="496" y="51" width="150" height="54" rx="8"/>
  <text class="t" x="571" y="75" text-anchor="middle">your process</text>
  <text class="s" x="571" y="92" text-anchor="middle">uses the value</text>

  <path class="e" d="M184,78 L261,78" marker-end="url(#fd-a)"/>
  <text class="el" x="222" y="69" text-anchor="middle">look up</text>
  <path class="e val" d="M415,78 L492,78" marker-end="url(#fd-av)"/>
  <text class="el val" x="453" y="69" text-anchor="middle">inject</text>

  <text class="s" x="340" y="135" text-anchor="middle">The value enters the process directly — never disk, argv, or screen.</text>
</svg>
</figure>

## An agent using a secret (MCP)

The flagship flow. An AI agent works under a [scope](/concepts/agent-scope/): it
reads **metadata** and can have kovra **inject** secrets into the commands it runs,
so they work — but the sensitive **plaintext never enters the model's context**,
the one place a prompt-injection attack could exfiltrate it.

<figure class="flow-diagram">
<svg viewBox="0 0 680 200" role="img" aria-label="Agent-over-MCP flow">
  <rect class="bound" x="14" y="42" width="182" height="120" rx="10"/>
  <text class="bl" x="26" y="34">Model context</text>

  <rect class="box" x="40" y="74" width="150" height="54" rx="8"/>
  <text class="t" x="115" y="98" text-anchor="middle">AI agent</text>
  <text class="s" x="115" y="115" text-anchor="middle">the model</text>

  <rect class="box core" x="300" y="70" width="150" height="66" rx="8"/>
  <text class="t" x="375" y="98" text-anchor="middle">kovra core</text>
  <text class="s" x="375" y="118" text-anchor="middle">scope · policy · vault</text>

  <rect class="box" x="512" y="74" width="150" height="54" rx="8"/>
  <text class="t" x="587" y="98" text-anchor="middle">child process</text>
  <text class="s" x="587" y="115" text-anchor="middle">runs the command</text>

  <path class="e" d="M196,96 L294,96" marker-end="url(#fd-a)"/>
  <text class="el" x="245" y="87" text-anchor="middle">metadata · run</text>

  <path class="e val" d="M450,103 L506,103" marker-end="url(#fd-av)"/>
  <text class="el val" x="478" y="94" text-anchor="middle">inject</text>

  <path class="e no" d="M300,150 L202,150" marker-end="url(#fd-an)"/>
  <text class="el no" x="250" y="182" text-anchor="middle">plaintext never returns to the model</text>
</svg>
</figure>

## Revealing a secret to a human

Sometimes *you* need the value yourself. A reveal is judged by sensitivity: an
ordinary secret is shown; a `high` one is shown only after a <span class="bioprove">bioProve</span>; the most protected (`inject-only`) is **never shown** — it can only
be injected. An agent can never trigger this for you.

<figure class="flow-diagram">
<svg viewBox="0 0 680 216" role="img" aria-label="Human reveal flow">
  <rect class="box" x="24" y="84" width="150" height="54" rx="8"/>
  <text class="t" x="99" y="108" text-anchor="middle">you</text>
  <text class="s" x="99" y="125" text-anchor="middle">at the terminal</text>

  <rect class="box core" x="250" y="78" width="150" height="66" rx="8"/>
  <text class="t" x="325" y="106" text-anchor="middle">policy check</text>
  <text class="s" x="325" y="126" text-anchor="middle">by sensitivity</text>

  <rect class="box ok" x="474" y="22" width="186" height="48" rx="8"/>
  <text class="t" x="567" y="43" text-anchor="middle">shown</text>
  <text class="s" x="567" y="60" text-anchor="middle">low · medium</text>

  <rect class="box" x="474" y="88" width="186" height="48" rx="8"/>
  <text class="t" x="567" y="109" text-anchor="middle">confirm, then shown</text>
  <text class="s" x="567" y="126" text-anchor="middle">high → bioProve</text>

  <rect class="box no" x="474" y="154" width="186" height="48" rx="8"/>
  <text class="t" x="567" y="175" text-anchor="middle">never shown</text>
  <text class="s" x="567" y="192" text-anchor="middle">inject-only</text>

  <path class="e" d="M174,111 L244,111" marker-end="url(#fd-a)"/>
  <text class="el" x="209" y="102" text-anchor="middle">request</text>

  <path class="e" d="M400,100 L437,100 L437,46 L468,46" marker-end="url(#fd-a)"/>
  <path class="e" d="M400,111 L468,111" marker-end="url(#fd-a)"/>
  <path class="e no" d="M400,122 L437,122 L437,178 L468,178" marker-end="url(#fd-an)"/>
</svg>
</figure>

## Sharing a secret set (sealed package)

To hand secrets to someone else, kovra **seals** a non-production set to the
recipient's public key. Only that recipient can open it — with **their own
identity** — and a separate one-time **access token** travels a different channel
to authorize the most sensitive entries. Production secrets are refused outright.

<figure class="flow-diagram">
<svg viewBox="0 0 680 190" role="img" aria-label="Sealed sharing flow">
  <rect class="box" x="20" y="50" width="150" height="54" rx="8"/>
  <text class="t" x="95" y="74" text-anchor="middle">your vault</text>
  <text class="s" x="95" y="91" text-anchor="middle">a non-prod set</text>

  <rect class="box core" x="246" y="44" width="150" height="66" rx="8"/>
  <text class="t" x="321" y="72" text-anchor="middle">kovra · seal</text>
  <text class="s" x="321" y="92" text-anchor="middle">to recipient's key</text>

  <rect class="box" x="500" y="50" width="156" height="54" rx="8"/>
  <text class="t" x="578" y="74" text-anchor="middle">recipient</text>
  <text class="s" x="578" y="91" text-anchor="middle">opens with own key</text>

  <rect class="box" x="246" y="130" width="150" height="40" rx="8"/>
  <text class="t" x="321" y="148" text-anchor="middle">access token</text>
  <text class="s" x="321" y="162" text-anchor="middle">separate channel</text>

  <path class="e" d="M170,77 L242,77" marker-end="url(#fd-a)"/>
  <path class="e val" d="M396,77 L496,77" marker-end="url(#fd-av)"/>
  <text class="el val" x="446" y="68" text-anchor="middle">sealed package</text>
  <path class="e tok" d="M396,150 L482,150 L482,98 L500,98" marker-end="url(#fd-at)"/>
  <text class="el tok" x="434" y="142" text-anchor="middle">high entries</text>

  <text class="el no" x="340" y="185" text-anchor="middle">Production secrets are refused — never packaged.</text>
</svg>
</figure>

## Bootstrapping a new machine (USB exchange)

The full offline handoff to a machine that has no kovra yet. The USB stick makes
**two trips** — out with the tooling, back with the destination's identity, out
again with the sealed package — and the **access token travels separately**. Every
destructive or sensitive step is gated by a <span class="bioprove">bioProve</span>, and production is excluded.

<figure class="flow-diagram">
<svg viewBox="0 0 680 300" role="img" aria-label="USB offline exchange — collaboration diagram">
  <rect class="box" x="40" y="18" width="200" height="44" rx="8"/>
  <text class="t" x="140" y="40" text-anchor="middle">Origin</text>
  <text class="s" x="140" y="55" text-anchor="middle">has kovra + vault</text>
  <rect class="box core" x="310" y="22" width="60" height="34" rx="6"/>
  <text class="t" x="340" y="44" text-anchor="middle">USB</text>
  <rect class="box" x="440" y="18" width="200" height="44" rx="8"/>
  <text class="t" x="540" y="40" text-anchor="middle">Destination</text>
  <text class="s" x="540" y="55" text-anchor="middle">no kovra yet</text>
  <path class="e" d="M240,40 L308,40"/>
  <path class="e" d="M372,40 L440,40"/>
  <path class="lane" d="M140,62 L140,210"/>
  <path class="lane" d="M540,62 L540,210"/>
  <text class="el" x="340" y="84" text-anchor="middle">format · kovra binary · install.sh</text>
  <path class="e" d="M156,92 L524,92" marker-end="url(#fd-a)"/>
  <circle class="badge" cx="140" cy="92" r="10"/><text class="badge-t" x="140" y="96" text-anchor="middle">1</text>
  <text class="el" x="340" y="118" text-anchor="middle">install · keygen → recipient.pub</text>
  <path class="e" d="M524,126 L156,126" marker-end="url(#fd-a)"/>
  <circle class="badge" cx="540" cy="126" r="10"/><text class="badge-t" x="540" y="130" text-anchor="middle">2</text>
  <text class="el val" x="340" y="152" text-anchor="middle">sealed package · prod refused</text>
  <path class="e val" d="M156,160 L524,160" marker-end="url(#fd-av)"/>
  <circle class="badge" cx="140" cy="160" r="10"/><text class="badge-t" x="140" y="164" text-anchor="middle">3</text>
  <text class="el tok" x="340" y="186" text-anchor="middle">access token · separate channel</text>
  <path class="e tok" d="M156,194 L524,194" marker-end="url(#fd-at)"/>
  <circle class="badge" cx="140" cy="194" r="10"/><text class="badge-t" x="140" y="198" text-anchor="middle">4</text>
  <path class="e val" d="M540,210 L540,222" marker-end="url(#fd-av)"/>
  <rect class="box ok" x="432" y="224" width="212" height="46" rx="8"/>
  <text class="t" x="538" y="245" text-anchor="middle">open: import</text>
  <text class="s" x="538" y="261" text-anchor="middle">custodied identity + token</text>
  <circle class="badge" cx="444" cy="230" r="10"/><text class="badge-t" x="444" y="234" text-anchor="middle">5</text>
  <text class="s" x="340" y="290" text-anchor="middle">Every destructive step is gated by a bioProve · production is excluded.</text>
</svg>
</figure>

## Authenticating with a custodied key (ssh-agent)

kovra can act as a governed ssh-agent: an SSH or git client sends a challenge,
kovra signs it **in memory** with a custodied key, and returns the signature. The
**private key never leaves kovra** and never touches disk; `high`/`prod` keys
require a confirmation on **every** signature.

<figure class="flow-diagram">
<svg viewBox="0 0 680 168" role="img" aria-label="Governed ssh-agent flow">
  <rect class="box" x="100" y="52" width="180" height="62" rx="8"/>
  <text class="t" x="190" y="79" text-anchor="middle">ssh / git client</text>
  <text class="s" x="190" y="97" text-anchor="middle">needs to authenticate</text>

  <rect class="box core" x="390" y="46" width="190" height="74" rx="8"/>
  <text class="t" x="485" y="79" text-anchor="middle">kovra ssh-agent</text>
  <text class="s" x="485" y="99" text-anchor="middle">holds the key</text>

  <path class="e" d="M280,76 L384,76" marker-end="url(#fd-a)"/>
  <text class="el" x="332" y="67" text-anchor="middle">challenge</text>
  <path class="e val" d="M384,98 L280,98" marker-end="url(#fd-av)"/>
  <text class="el val" x="332" y="112" text-anchor="middle">signature</text>

  <text class="s" x="340" y="148" text-anchor="middle">Signed in memory — the private key never leaves kovra; high/prod confirm each time.</text>
</svg>
</figure>

## Administering from the browser (Web UI)

An on-demand admin UI, launched behind a confirmation and bound to **loopback
only**. It shows ordinary values but **never renders** the plaintext of `high` or
`inject-only` secrets — those appear masked, with a fingerprint, and reveal only
through the CLI.

<figure class="flow-diagram">
<svg viewBox="0 0 680 196" role="img" aria-label="Web UI flow">
  <rect class="box" x="24" y="80" width="150" height="54" rx="8"/>
  <text class="t" x="99" y="104" text-anchor="middle">browser</text>
  <text class="s" x="99" y="121" text-anchor="middle">127.0.0.1 only</text>

  <rect class="box core" x="246" y="74" width="150" height="66" rx="8"/>
  <text class="t" x="321" y="102" text-anchor="middle">kovra Web UI</text>
  <text class="s" x="321" y="122" text-anchor="middle">loopback admin</text>

  <rect class="box ok" x="474" y="46" width="186" height="48" rx="8"/>
  <text class="t" x="567" y="67" text-anchor="middle">values shown</text>
  <text class="s" x="567" y="84" text-anchor="middle">low · medium</text>

  <rect class="box no" x="474" y="116" width="186" height="48" rx="8"/>
  <text class="t" x="567" y="137" text-anchor="middle">masked + fingerprint</text>
  <text class="s" x="567" y="154" text-anchor="middle">high · inject-only</text>

  <path class="e" d="M174,107 L240,107" marker-end="url(#fd-a)"/>
  <path class="e" d="M396,100 L435,100 L435,70 L468,70" marker-end="url(#fd-a)"/>
  <path class="e no" d="M396,114 L435,114 L435,140 L468,140" marker-end="url(#fd-an)"/>

  <text class="s" x="340" y="186" text-anchor="middle">Loopback only — never exposed to the network.</text>
</svg>
</figure>
