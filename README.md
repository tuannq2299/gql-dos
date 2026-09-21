# GraphQL DoS Probe

Burp extension for testing GraphQL query-cost controls. Two tabs:

- **Generator** — builds a payload at a chosen size for the vectors the scan left open.
- **Scanner** — detects which cost limits are missing, without applying load.

Neither tab attacks anything on its own. The scanner sends seven tiny probes; the
generator sends nothing at all — you fire from Repeater when you choose to.

No AI, no credits, no outbound calls of its own. Works in Burp Community.

## Install

Build it:

```
./gradlew jar
```

That writes `build/libs/gql-dos-1.0.0.jar`. Run the tests with `./gradlew test`. Load it via
**Extensions → Installed → Add → Extension type: Java**. A tab named **GraphQL DoS**
appears.

The jar targets Java 17 bytecode, so Burp's bundled JRE runs it as-is. Building needs a
JDK 17 or newer; the Gradle wrapper fetches Gradle itself. Bump the `montoya-api`
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

The introspection probe runs first and reports the endpoint's query root type. Two later
probes have to name that type, and it is only called `Query` by convention — Shopify uses
`QueryRoot`. The remaining probes are rebuilt around whatever name comes back, so they
test the control instead of failing on an unknown type.

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

With **File findings as Burp issues** left on, every missing control is added to Burp's
Issues view and the site map when the scan finishes, with the probe's request and
response attached as evidence. Controls that fired are not filed — a control that works
is not a finding, and filing it would bury the ones that matter.

### Reading the verdicts

| Verdict | Meaning |
|---|---|
| **No limit** | payload accepted — the control is absent |
| **Limited** | rejected by a limit, with the server's message as evidence |
| **Inconclusive** | errored for an unrelated reason, or never reached the server |
| **Error** | 5xx or no response |

Five things to not misread:

- **Scan authenticated.** Limits are often applied to anonymous traffic only. An
  unauthenticated scan can report the front door locked while the real path is open.
- **`429` reports as Limited, but rate limiting is not cost limiting.** It doesn't help
  when a single request is the attack. Treat it as a separate control.
- **`Error` on a zero-cost probe is its own finding.** Something broke without being
  asked to do any work.
- **Depth needs introspection.** With it disabled you get Inconclusive — supply a known
  recursive edge in the Generator's Schema fields tab instead.
- **A WAF answering instead of the server is Inconclusive, not Limited.** A 4xx with no
  GraphQL body means the request never reached the resolver, so it says nothing about
  the endpoint's cost controls. `413` is the exception and reports Limited: a body-size
  ceiling is a real control, wherever it is enforced.

One verdict is worth more than the rest. A compliant validator rejects the fragment
cycle and a broken one never comes back, so the fragment-cycle probe's interesting
result arrives as **Error**, not as No limit. The summary and the issue list both call
that case out: a validator you hung with 200 unauthenticated bytes and zero resolver
work is the strongest thing this scan can find. Time it in Repeater before writing up
anything else.

Evidence for **Limited** is matched against the `message` values inside the GraphQL
`errors` array, not the whole response. Words like `cost` and `limit` appear in ordinary
result data — Apollo returns a cost breakdown in `extensions` on success — and matching
those would report a control that is not there.

---

## Generator

Pick a **Vector**, set **Count (N)**, click **Generate payload**, then
**Copy to clipboard** or **Send to Repeater**. Nothing is sent until you press Send
in Repeater.

The payload box is a preview and is read-only; past 512 KB it shows the first 512 KB and
says so. Copy and Send to Repeater always use the whole payload. Edit in Repeater, where
what you see is what gets sent. Changing any input clears the preview, so the buttons
can't hand out a payload the form no longer describes.

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

**Cycle field** and **Type name** are also read by the three recursion vectors when you
are on the Captured request tab. A captured client query has no recursive edge in it —
one that did would already be the interesting query — so the edge has to come from here.
Those vectors then combine it with the captured operation's own header, root field and
arguments, and the envelope is preserved as usual, variables included. The captured
selection set is replaced, and the original document's fragment definitions are dropped
with it: an unused fragment is a validation error, and being rejected for that would
tell you nothing about the control you're testing.

| Field | Role | Example |
|---|---|---|
| Root field | entry point with args *(schema mode; captured mode uses the captured field)* | `user(id:1)` |
| Leaf field | terminal scalar | `name` |
| Cycle field | self-referencing edge *(both modes)* | `friends` |
| Type name | what the cycle field returns *(both modes)* | `User` |
| Fan-out | refs per level *(nested+alias only)* | `2` |

Source these from introspection or InQL's circular-reference output. In schema mode the
arguments must be inline literals — there is no variables object — so it's awkward for
operations taking input objects. Drive those from the Captured request tab instead,
which keeps the real `variables`.

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

The three marked *yes* need **Cycle field** set, and the two fragment-based ones need
**Type name** as well. They work from either tab. If the schema has no self-referencing
edge, the vector genuinely doesn't apply and there is nothing to fill in.

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
request before the server costs it, which is easy to misread as "protected." Past 32 MB
the payload is refused outright, before anything is allocated — an N that large is a
typo, and building it would cost Burp more than it costs the target.

Generation runs off the UI thread, so a large N doesn't freeze Burp.

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

---

## Development

```
./gradlew test    # 56 tests: payload construction, verdict classification, parsing
./gradlew jar     # build/libs/gql-dos-1.0.0.jar
```

No runtime dependencies. `montoya-api` is `compileOnly` — Burp provides it — so the jar
ships nothing but this extension's own classes. JUnit is test-scoped and never reaches
the jar.

The verdict classifier is where the tests earn their place: a wrong verdict is worse
than no verdict, because it goes in a report. Cases with a named regression are marked
as such in the test bodies.

---

## License

MIT. See [LICENSE](LICENSE).
