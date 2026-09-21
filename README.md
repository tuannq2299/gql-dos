# GraphQL DoS Probe

Burp extension for testing GraphQL query-cost controls. Two tabs:

- **Scanner** — detects which cost limits are missing, without applying load.
- **Generator** — builds a payload at a chosen size for the vectors the scan left open.

Neither tab attacks anything on its own. The scanner sends seven tiny probes; the
generator sends nothing at all — you fire from Repeater when you choose to.

## Install

Load `gql-dos-1.0.jar` via **Extensions → Installed → Add → Extension type: Java**.
A tab named **GraphQL DoS** appears. Java 17+ (Burp's bundled JRE is fine).

To rebuild: `./gradlew jar` → `build/libs/gql-dos-1.0.jar`. Bump the `montoya-api`
version in `build.gradle` to match your Burp if it fails to load.

---

## Workflow

1. Capture a GraphQL request in Burp.
2. Right-click → **Send to GraphQL DoS Probe**. URL, auth headers and the request body
   populate both tabs.
3. **Scanner** → Run scan. Find out which controls are absent.
4. **Generator** → pick a vector the scan left open, set N, generate, send to Repeater.
5. Step N up in Repeater and watch the response timer.

---

## Scanner

Add the target to Burp scope (the scope guard blocks otherwise), then **Run scan**.
Seven requests, ~87 KB total.

Every probe resolves only `__typename` or an introspection meta-field, so it costs the
server nothing — you're testing the validator, not the resolvers. A 100-alias
`__typename` query returning 200 proves there is no alias cap while executing zero
business logic.

| Probe | Tells you |
|---|---|
| Introspection | schema is readable, recursive edges discoverable |
| Alias limiting | no cap on aliased field count |
| Field duplication | duplicates not collapsed before costing |
| Depth limiting | nesting depth unchecked *(needs introspection)* |
| Batch limiting | array batching accepted |
| Fragment cycle rejection | validator not enforcing the spec rule |
| Request size limiting | no body-size ceiling |

Click any row for the rationale and the exact payload sent.
**Copy findings** puts a Markdown table on the clipboard, plus a summary naming which
generator vectors are open.

### Reading the verdicts

| Verdict | Meaning |
|---|---|
| **No limit** | payload accepted — the control is absent |
| **Limited** | rejected by a limit, with the server's message as evidence |
| **Inconclusive** | errored for an unrelated reason; not evidence either way |
| **Error** | 5xx or no response |

Four things to not misread:

- **Scan authenticated.** Limits are often applied to anonymous traffic only. An
  unauthenticated scan can report the front door locked while the real path is open.
- **`429` reports as Limited, but rate limiting is not cost limiting.** It doesn't help
  when a single request is the attack. Treat it as a separate control.
- **`Error` on a zero-cost probe is its own finding.** Something broke without being
  asked to do any work.
- **Depth needs introspection.** With it disabled you get Inconclusive — supply a known
  recursive edge in the Generator's Schema fields tab instead.

---

## Generator

Pick a **Vector**, set **Count (N)**, click **Generate payload**, then
**Copy to clipboard** or **Send to Repeater**. Nothing is sent until you press Send
in Repeater.

### Captured request (default tab)

Paste the request body exactly as Burp shows it. The JSON envelope is kept byte-for-byte
and only the `"query"` value is replaced, so `operationName`, `variables` and
`extensions` all survive. The operation name is preserved too — renaming it would break
the envelope's `operationName`.

A bare GraphQL operation also works; a minimal envelope is synthesised, but variables
are then absent, so paste the full body for anything variable-driven.

> If the endpoint uses APQ, delete `extensions` before generating — a modified `query`
> with an unchanged `sha256Hash` will be rejected on hash mismatch.

### Schema fields (second tab)

For building payloads with no captured traffic, or for shapes the client never sends.
Three vectors need recursion that a captured query doesn't contain, and this is the only
way to reach them.

| Field | Role | Example |
|---|---|---|
| Root field | entry point with args | `user(id:1)` |
| Leaf field | terminal scalar | `name` |
| Cycle field | self-referencing edge | `friends` |
| Type name | what the cycle field returns | `User` |
| Fan-out | refs per level *(nested+alias only)* | `2` |

Source these from introspection or InQL's circular-reference output. Arguments must be
inline literals here — there is no variables object — so it's awkward for operations
taking input objects.

### Vectors

| Vector | N controls | Needs a recursive edge |
|---|---|---|
| Alias overload | aliases | no |
| Field duplication | repeats | no |
| Deep nesting | nesting levels | **yes** |
| Circular fragments | fragments in the cycle | **yes** |
| Directive overload | directives | no |
| Array batching | operations | no |
| Deep introspection | `ofType` levels | no |
| Nested + alias | **depth** (nodes = fan-out^N) | **yes** |

The three marked *yes* fail with a clear message if the schema has no self-referencing
field. That's not a bug — the vector genuinely doesn't apply.

**Nested + alias** is the one worth reaching for when it's available. Layered fragments
keep the request linear in size while server-side expansion is exponential: fan-out 2 at
depth 30 is a 2.2 KB request asking for ~1.07 billion resolver nodes. That
request-to-work ratio is the number to put in a report.

### Alias prefix

Aliases are `prefix + index` — default `a0:`, `a1:`. If a WAF matches that pattern you
get a flat curve that looks exactly like a properly limited endpoint. Changing the
prefix separates the two cases. Worth doing whenever results go flat sooner than
expected.

---

## Sizing

Work up in steps — 10, 50, 100, 500 — and watch Repeater's response timer. You're
looking for where response time stops tracking payload size. An unbounded cost curve is
the proof; you don't need to take the service down, and a curve is better evidence than
an outage you then have to explain.

Cost per alias is the size of the field you're multiplying. For a 1.3 KB operation:

| N | request size |
|---|---|
| 100 | ~133 KB |
| 500 | ~660 KB |
| 1,000 | ~1.3 MB |
| 10,000 | ~13 MB |

Past ~5 MB the status line warns you: a proxy or body-size limit will usually reject the
request before the server costs it, which is easy to misread as "protected."

Trimming the selection set to a single scalar roughly halves the bytes per alias. If the
expensive work happens in the root resolver, you keep full server cost at half the size.
Check that assumption by timing N=50 trimmed against N=50 full — matching times mean the
work is in the root resolver and you can trim freely.

---

## Reporting

Maps to **OWASP API4:2023 Unrestricted Resource Consumption**.

Typical scoring: CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High**
unauthenticated; `PR:L` → **6.5 Medium** where auth is required.

Root cause is nearly always the same: the resolver executes before any cost ceiling is
applied. Remediation is depth limiting plus static query cost analysis
(`graphql-depth-limit`, `graphql-cost-analysis`, Apollo `maxQueryDepth`, or persisted
queries) — not rate limiting, which doesn't help when one request is the attack.

For the PoC, use the smallest N that shows clear degradation, not the largest you fired.

Confirm resource exhaustion is in scope first. Many YesWeHack and HackerOne programs
exclude DoS outright, and on a shared staging environment a ramp will show up in APM
before it shows up in your results.