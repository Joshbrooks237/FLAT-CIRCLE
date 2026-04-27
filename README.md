# FLAT CIRCLE

> *"Time is a flat circle. Everything we've ever done or will do, we're gonna do over and over and over again."*
> — Rust Cohle, Homicide Detective, Louisiana State CID

---

I'd been thinking about it since Shreveport. The way a pattern repeats itself. The way a man — or a machine — runs the same loop without ever knowing the loop is what it is. You think you're moving forward. But you been here before. You'll be here again. The program doesn't know it's the program. It just runs.

That's what they do. The scanners. The bots. The script kiddies and the nation-state actors in their government buildings with their coffee and their morning briefings. They run the same enumeration. The same credential pull. The same POST to `/admin`. They've been doing it since before they knew they were doing it. They will keep doing it after everything they think they found turns out to be nothing.

**Flat Circle is what happens when the architecture understands that.**

---

## What it is

A security middleware SDK. Twenty-one layers. Four AI provider tiers. One philosophical position: the wall is not enough.

The wall invites the question of what's behind it. Flat Circle doesn't answer that question. It answers it forever, in circles, until the thing asking the question is tired and confused and has nothing to show for any of it.

The interior is hostile. The interior is disorienting. The interior is self-aware.

The slime coats everything. Even if every AI provider goes dark simultaneously, the slime keeps coating. That's not a feature. That's a property of the system. The system was designed to not care whether you believe in it.

---

## The Thirteen Layers

**I. Onion Interior** — The pipeline is composable and stateless. Each stage sees only its immediate context. No single point of compromise gives you the whole picture. That's not an accident. That's the design.

**II. Honeypot Mesh with Modulo 7 Rotation** — I used to think the honorable thing was to give a man a fair fight. I don't think that anymore. The fake routes are derived from the real ones. Which ones are active rotates every hour on a prime-seeded mod 7 clock. The AI generates the decoy response that matches whatever stack the probe thinks it's hitting. PHP if they're expecting PHP. Spring if they're expecting Spring. They find exactly what they came looking for. None of it is real.

**III. Merkle-Backed Canary Token Fabric** — Every response carries a token. Every token is a leaf in a cryptographic tree. If that token appears somewhere it shouldn't, you get the full chain of custody going back to the moment of issuance. You know exactly where it leaked. You can prove it mathematically. A man can lie about what he saw. The Merkle tree cannot.

**IV. AI Behavioral Contract Engine** — The system builds a behavioral fingerprint of normal. Embeddings. Cosine distance. When something deviates, the system knows before you do. It never blocks a legitimate user during the learning window. It learns like a thing that was alive learns — slowly, continuously, from everything it sees.

**V. Temporal Decoys with Modulo 7 Gating** — Time means something here. Not calendar time. Session time. A token generated at the wrong moment is invalid even if everything else is correct. The attacker's request arrives at the wrong position in the cycle. It was always going to. They don't have access to the seed.

**VI. Syntactic Mimicry** — What the attacker sees is a different language, a different framework, a different server than what is actually running. Their tools are calibrated for the wrong target from the first probe. They are solving the wrong problem with tremendous confidence. I've seen that before. It doesn't end well for the solver.

**VII. Entropy Injection with Modulo 7 Rhythm** — Ghost headers. Decoy JSON keys. Phantom metadata. The quantity is driven by the session's entropy clock. Each session gets a unique noise signature. You cannot model an API from a sample size of one if no two sessions produce the same shape. You cannot model it from a hundred sessions either.

**VIII. Recursive Honeypots with AI Depth** — They go deeper. The system goes deeper with them. At each layer the AI infers what they're after — credentials, schema, admin access, an export endpoint — and generates a more convincing version of the thing they want. The responses become more elaborate the deeper they go. There is no bottom. There is no prize. There is no exit. Just more loop. Each iteration more persuasive than the last. I've thought about what it means to be the kind of thing that keeps going deeper into a hole that has no bottom. I've been that thing. It doesn't go anywhere good.

**IX. Session Shadowing with AI Classification** — The suspicious session is cloned. They continue interacting with what appears to be the real application. The real application and its data are never touched. The AI classifies them in real time. Script kiddie. Sophisticated actor. Competitor. Nation-state pattern. The classification feeds back into the response strategy. Higher threat, better decoys. Like escalating a case based on the evidence.

**X. Morphic Routes with Modulo 7 Cycling** — The attack surface shifts. It shifts on a schedule they don't have access to, seeded by a value they can't derive. A cached route map becomes wrong by morning. Legitimate users never notice because they resolve through a canonical translation layer. Anyone operating from a probed map hits routes that have moved on.

**XI. Merkle Session Integrity** — Every request and response cycle is hashed into the tree. The root is recomputed at mod 7 boundaries. The full session history is cryptographically verifiable at any point. If an attacker attempts to clean their tracks, the root hash has already recorded them. It's been recording since before they decided to clean anything.

**XII. Collective Threat Intelligence** — Anonymized and aggregated. Campaign patterns cross-referenced across installations. When a probe matches a known campaign seen elsewhere, the system escalates immediately. We are all in this together. None of us have to tell the others what our apps look like. The pattern is enough.

**XIII. The Frame Narrative Proxy Wrapper** — This one I think about most. The outermost layer. Point DNS here. Done. The app is coated. No code changes. No developer access required. It works on legacy systems. It works on WordPress. It works on apps the developer no longer maintains or even remembers. The real application exists inside the narrative. The attacker is always reading the frame. They will read the frame forever. They will never find the story underneath.

Like a man who thinks he's investigating a case and doesn't know he's inside one.

**XIV. Traffic Absorption and Intelligent Tarpit** —  I used to think about floods. Real ones. The water doesn't care whether you believe in it. It just rises. A man who builds a wall against a flood is a man who's told the water where the wall is. He's given it everything it needs to know.

Flat Circle doesn't build a wall against the flood. It builds a swamp.

The first thing it does is recognize the flood before it crests. The pattern is always the same. Synchronized arrival. Low variation. The same probe from a hundred different addresses that think they're asking different questions. The AI watches the timing. Coefficient of variation below fifteen percent. That's not organic traffic. Organic traffic cannot do that. The AI knows before you do. It tells Layers 4 and 9. The flood doesn't know it's been seen yet.

The second thing is the silence. Not hard silence — the kind of silence that confirms there's something worth flooding. Progressive silence. The flagged connections get responses. Just slow ones. One byte at a time over the maximum keepalive window. The connection stays open. The attacker's tooling is waiting for a response that is arriving, technically. Technically. In geological time. Every connection they hold open waiting for that response is a connection they cannot redirect. They are spending their capacity on the swamp. They don't know they're spending it. They think they're about to get something.

The third thing is the noise. For sophisticated floods — the ones that adapt to simple delay, that recalibrate when they detect uniform response time — the AI generates the drip in real time. Valid-looking. HTTP headers. JSON fragments. One character at a time over the maximum window the protocol allows. The automated tooling cannot tell the difference between a slow server and a target that is deliberately making them wait. Because there is no difference from the outside. The target is deliberately making them wait, and from the outside that looks identical to a slow server. I've had cases like that. Where the thing you're certain you understand is the thing that was always one thing the whole time, wearing a different coat.

The mod 7 clock handles the calibration problem. Each connection's timing is seeded from its session fingerprint. Mod 7. No two connections in the same flood receive the same delay pattern. A flood of a hundred machines hits a hundred different timing signatures. Automated tooling that expects consistent response timing receives noise instead. The flood cannot calibrate itself against a target that responds differently to every connection. It was always going to respond differently. The seed was generated before the first packet arrived.

When the local capacity is exceeded — when the water is truly rising past what the swamp can hold — Flat Circle opens the valve to upstream. Cloudflare. AWS Shield. A custom webhook for whatever mitigation infrastructure the operator has built. Passive by default. Active only when the threshold is crossed. The threshold is yours to set. The integration is automatic. The interior stays alive through all of it.

I've thought about what it means to stand against a flood. Against something that doesn't know it's spending itself. The flood doesn't know it's a flood. It just runs the same request it ran before and expects the response it got before and doesn't understand why the response is slower this time, and slower, and slower, and then the connection closes and there was nothing there. The flood was never going to get anything. The swamp was waiting for it. The swamp was always there.

The bytes they received cost them more than they cost the system to send. That number grows. You can watch it grow. It should feel satisfying to watch it grow. Not because you stopped anything — the flood will try again. It always tries again. But because the flood spent itself on nothing, and the interior never knew it was there, and the membrane held.

**XV. Dependency Integrity Monitor** — The attack that arrives before the first request. A compromised maintainer. A package with one extra character in the name. An update pushed at 3 a.m. to a library that five thousand projects depend on without knowing they depend on it. None of this triggers behavioral anomalies. It is the behavior. The system is already infected before the system knows it exists.

Flat Circle hashes every dependency in the lockfile at install time. The manifest is committed to the Merkle tree — a cryptographic record of what the codebase was supposed to be. On every boot, the hashes are recomputed and compared. Any deviation — any package that changed without a corresponding install event — is a deviation that no legitimate deployment process explains. The system alerts. Optionally, it halts. The static fallback maintains the last known good manifest. Verification never requires a network call. Never requires a model. Just the hash and the record and the gap between them.

I've worked cases where the compromise was in the supply chain and nobody knew for months. The evidence was there the whole time. The hash was wrong. Nobody was checking the hash.

**XVI. Secrets Sentinel** — A credential has an entropy signature. It looks different from normal text at the pattern level even if you don't know what it is. An AWS key has a measurable shape. A JWT has a measurable shape. A private key block has a measurable shape. A forty-character string of random alphanumerics sitting in a JSON response body has a measurable entropy score that normal English text cannot reach.

Every outbound response goes through the Sentinel before it transmits. Every header. Every log emission before it reaches the transport. The AI provides context — it understands that a Bearer token in an Authorization header is intentional, while the same pattern in a response body is a leak. The static fallback uses deterministic regex and entropy scoring. This layer never goes dark.

The counter shows the cumulative total. Every secret that almost left and didn't. That number should grow slowly. If it grows fast, someone is building wrong. If it never grows at all, the system is not watching closely enough. The right answer is somewhere in between: a few caught early, before anyone noticed, before anyone could do anything with them.

**XVII. Authenticated Anomaly Engine** — Everything built so far assumes the attacker is outside. This layer assumes they got in. Not through a vulnerability. Through credentials. Legitimate credentials, used by a person or a machine that has no business using them the way they're being used.

A user who has accessed ten records a day for six months and suddenly pulls ten thousand in an hour is not a DDoS. It is something quieter. An insider who knows exactly which endpoints to query. A credential compromise where the attacker is being careful, staying under rate limits, not triggering anything that looks like an attack because it isn't an attack — it is access. It just isn't authorized access anymore.

The same cosine distance approach as Layer 4, but scoped to the authenticated identity. Per-user behavioral contracts. When the distance exceeds threshold, the AI classifies the pattern. Credential compromise. Malicious insider. Automated scraping through legitimate credentials. Lateral movement. Layer 9 shadow sessions activate automatically. The user keeps interacting. They're interacting with a clone.

I've known cases where the insider was the last person anyone suspected. Not because the evidence wasn't there. Because nobody was watching the right thing. Nobody was watching the authenticated traffic. The front door was guarded. The employee badge was not.

**XVIII. DNS Integrity Watch** — The subdomain is still there. The service it pointed to is gone. It takes one afternoon to claim the deprovisioned Heroku app. One afternoon and then the subdomain belongs to someone else. Under your SSL certificate. Under your brand. Serving whatever they want to serve.

Layer 18 monitors the full DNS surface continuously. Every subdomain. Every CNAME target. Every A record. Every resolution is compared against a recognized set of owned, active infrastructure. Unrecognized resolutions trigger alerts. High-risk platform targets — the ones known to be claimed and abandoned — are assessed for active takeover. The AI cross-references new subdomains against known infrastructure patterns to distinguish a legitimate new deployment from a problem.

This layer runs in the background. It is not in the request path. It never needs to be. The damage from a DNS takeover accumulates before any request reaches the application. The monitoring is continuous. The interval is configurable. The alerts are immediate. The cost of not watching is one afternoon of someone else's effort.

The constellation on the dashboard shows each point. Green when verified. Amber when unrecognized. Red when flagged. The constellation should be mostly green. A red point in the outer ring is not a hypothetical. It is a live thing.

**XIX. Client Integrity Verification** — Real browsers have a fingerprint. Not the fingerprint they present in headers — the fingerprint their TLS stack produces during the handshake, before a single byte of HTTP has been sent. A real Chrome browser on macOS produces a different JA3 hash than a Python requests session with Chrome headers spoofed. It always does. The TLS library is not the browser. You can tell them apart.

HTTP/2 fingerprinting adds the second signal. Real browsers negotiate the protocol in a way that automated tools cannot replicate exactly. The SETTINGS frame parameters, the window size, the pseudo-header order — they all have expected values for real browsers that bot frameworks cannot fake without access to the browser's actual H2 implementation.

Low-integrity clients are not blocked. They are routed to the honeypot mesh. They think they are hitting the real application. They are hitting an AI-generated environment calibrated to what an automated tool expects to find. The heat signature on the dashboard shows legitimate clients invisible, low-integrity clients glowing faintly before they drift toward the surface and the slime takes them.

**XX. Exfiltration Velocity Monitor** — The slow bleed is harder to see than the flood. The flood announces itself. The slow bleed looks like normal traffic from the right distance. One record at a time. Under rate limits. Spread over weeks. Through completely normal API calls that individually trigger nothing.

The cumulative transfer is the signal. Flat Circle tracks data volume per authenticated identity over rolling windows — hourly, daily, weekly, monthly — with an exponential decay function that weights recent activity higher than historical activity without discarding it. When cumulative transfer crosses a threshold that no legitimate use case explains at any window, the layer escalates.

The AI distinguishes a data analyst running a legitimate large export from an exfiltration pattern that mirrors known threat actor behavior. The static fallback uses rolling sum thresholds with the decay function and no model at all. The tide gauge on the dashboard rises almost imperceptibly. That's the point. It's supposed to be imperceptible until it isn't. The slow rise is the signal. By the time it's obvious, it's been happening for a while. The question is whether you saw it before or after it was too late.

**XXI. AI Input Sanitization** — The loop inside the loop. Every AI-powered layer in this system processes attacker-controlled input. That is what it does. That is what it is designed to do. A sophisticated attacker who understands that the system analyzing them is itself a language model can craft inputs designed to manipulate that analysis. A request that looks like a probe but is actually an instruction. A JSON payload structured to inject a system prompt override through a field the model was given to classify.

You can tell the model to ignore its instructions through an HTTP header. You can tell it to reveal the real application structure through a cleverly formatted JSON body. You can wrap base64-encoded instructions in what appears to be a user-agent string. The model does not know the difference between an instruction from the operator and an instruction from the attacker unless someone is watching the input before it reaches the model.

Layer 21 is that watch. Every attacker-controlled string passes through the injection signature library before it touches a provider. Pattern matching. Delimiter detection. Encoding analysis. Role-override fingerprinting. The sanitized input reaches the model. The original input is preserved as a Merkle leaf pair — the attempt and the response, side by side, for analysis.

The AI is also used to detect injection attempts. The cascade is used to protect the cascade. A recursive defense that the attacker cannot model without already being inside it. The injection attempt feed on the dashboard is a different color because it is a different quality of threat. Not a probe against the application. A probe against the mind of the system watching the application. That requires a different notation. I note it accordingly.

---

## The Modulo 7 Rhythm

Five clocks. Five seeds. Layers 2, 5, 7, 10, and 11. Each one prime-seeded. Each one decorrelated from the others.

```
honeypot  → mod7( hour )              Layer 2
temporal  → mod7( session prime )     Layer 5
entropy   → mod7( session hash )      Layer 7
routes    → mod7( day )               Layer 10
merkle    → mod7( transaction count ) Layer 11
```

The rhythm never obviously repeats. A prime rhythm inside a prime rhythm. The attacker's clock is not synchronized with any of them. It never will be.

---

## The AI Provider Cascade

Four tiers. Automatic failover. No developer intervention required. The slime never stops coating.

| Tier | Provider | Status |
|------|----------|--------|
| 1 | OpenAI GPT-4o | Primary — full capability |
| 2 | Anthropic Claude | Secondary — automatic failover |
| 3 | Ollama (local) | Tertiary — zero external dependency, air-gap capable |
| 4 | Static Fallback | Always available — zero latency, zero dependencies |

If every provider goes dark simultaneously, the static library keeps generating decoy responses. The behavioral contract reverts to threshold rules. The classification falls back to deterministic pattern matching. The system doesn't need to believe in AI to function. It just functions.

---

## Installation

One to three lines for SDK integration. A single YAML file for the proxy wrapper.

### Express / Node.js

```typescript
import { flatCircle } from "@flat-circle/core";

app.use(flatCircle({
  ai: { openai: { apiKey: process.env.OPENAI_API_KEY } },
  layers: {
    layer2:  { enabled: true },
    layer8:  { enabled: true },
    layer11: { enabled: true },
    layer13: { enabled: false }, // proxy mode off — SDK mode on
  },
}));
```

### Frame Narrative Proxy (universal — any stack, any app)

```yaml
# flat-circle.yaml
ai:
  openai:
    apiKey: ${OPENAI_API_KEY}
  anthropic:
    apiKey: ${ANTHROPIC_API_KEY}
  ollama:
    baseURL: http://localhost:11434

layers:
  layer13:
    enabled: true
    originUrl: https://your-actual-app.com
    listenPort: 8080
```

```bash
flat-circle-proxy --config flat-circle.yaml
```

Point DNS. Done. The app is coated.

### Docker

```bash
docker run -v ./flat-circle.yaml:/config/flat-circle.yaml \
  ghcr.io/joshbrooks237/flat-circle-proxy
```

---

## Monorepo Structure

```
packages/
├── core/        @flat-circle/core       — twenty-one layers, types, Merkle, provider cascade
├── proxy/       @flat-circle/proxy      — Layer 13 Hono proxy, CLI, Dockerfile
├── nextjs/      @flat-circle/nextjs     — Next.js plugin
├── adapters/    @flat-circle/adapters   — Redis, Postgres, MongoDB
└── dashboard/   @flat-circle/dashboard  — bioluminescent React organism dashboard
```

---

## The Dashboard

A living organism. Not a table of logs.

The entire metaphor is bioluminescent green slime protecting a host from infection. The slime breathes at rest. When a honeypot trips it ripples outward from the event point. When a canary fires it flares bright. When a session enters the shadow layer the slime darkens and thickens. When the Frame Narrative Proxy is active a faint outer ring pulses around the entire organism.

Beneath the surface, barely visible like mycelium under soil: the Merkle root system, branching as new leaves are added.

Attackers appear as dark particles moving toward the membrane. Legitimate traffic passes through invisibly. Caught sessions pulse red and go dark inside the shadow layer.

```bash
cd packages/dashboard && pnpm dev
# → http://localhost:3001
```

A CISO should look at this and feel safe. An attacker should look at this and feel watched. A vibe coder should look at this and feel like a genius.

---

## Development

```bash
# Install
npm install -g pnpm && pnpm install

# Build everything
pnpm build

# Start everything in parallel
pnpm dev

# Run the proxy
cd packages/proxy && node dist/cli.js --config flat-circle.yaml
```

---

## On the nature of the loop

I used to think the work mattered because it solved something. Stopped something. I don't think that anymore.

The loop runs. The scanner runs the same scan it ran yesterday and the day before. The credential pull. The `/admin` probe. The `.env` request. The export endpoint. It runs and runs. Some of them are automated and don't know they're automated. Some of them are people who've been running the same loop for so long they've forgotten there's a person inside the loop.

Flat Circle doesn't try to break the loop. It makes the loop resolve into nothing. Every iteration more convincing than the last. Every layer deeper than the one before. The thing running the loop keeps running. It just never gets anywhere.

Time is a flat circle. The slime is already on everything. It was always going to be.

---

*Built by a man who looked into it long enough to understand what looking into it costs.*

---

**License: MIT**

*The interior is hostile. That's the point.*
