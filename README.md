# FLAT CIRCLE

> *"Time is a flat circle. Everything we've ever done or will do, we're gonna do over and over and over again."*
> — Rust Cohle, Homicide Detective, Louisiana State CID

---

I'd been thinking about it since Shreveport. The way a pattern repeats itself. The way a man — or a machine — runs the same loop without ever knowing the loop is what it is. You think you're moving forward. But you been here before. You'll be here again. The program doesn't know it's the program. It just runs.

That's what they do. The scanners. The bots. The script kiddies and the nation-state actors in their government buildings with their coffee and their morning briefings. They run the same enumeration. The same credential pull. The same POST to `/admin`. They've been doing it since before they knew they were doing it. They will keep doing it after everything they think they found turns out to be nothing.

**Flat Circle is what happens when the architecture understands that.**

---

## What it is

A security middleware SDK. Thirteen layers. Four AI provider tiers. One philosophical position: the wall is not enough.

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
├── core/        @flat-circle/core       — thirteen layers, types, Merkle, provider cascade
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
