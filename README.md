# GraphQL DoS Probe

Burp extension that generates GraphQL resource-consumption payloads at a chosen size
and hands them to Repeater or the clipboard. It does not send requests itself --
firing stays a deliberate act in Repeater.

Built on the Montoya API. Fills the gap InQL leaves: InQL gives you one batching
primitive and flags circular refs, but doesn't generate nesting, fragment, or
amplification payloads or produce a cost curve.

## Build

```bash
./gradlew jar
# -> build/libs/gql-dos-1.0.jar
```

Java 17+. Load in Burp via Extensions > Installed > Add > Java.
A prebuilt `gql-dos-1.0.jar` is included if you want to skip the build.

Bump the `montoya-api` version in `build.gradle` to match your Burp
(current at time of writing: `2026.7`).

## Use

Right-click any GraphQL request in Burp > **Send to GraphQL DoS Probe**. That pulls the
URL, auth headers and the **full request body** into the tab. Pick a vector, set
**Count (N)**, click **Generate payload**, then **Copy to clipboard** or **Send to Repeater**.

The JSON envelope is kept byte-for-byte and only the `"query"` value is replaced, so
`operationName`, `variables` and `extensions` (including APQ `persistedQuery` hashes)
survive untouched. The operation name is preserved too -- renaming it would break the
envelope's `operationName` and make the payload stand out in traffic.

If you paste a bare GraphQL operation instead of a JSON body, a minimal envelope with
`operationName` and `query` is synthesised.

The **Schema fields** tab is for building payloads without a captured request:

| Field | Meaning | Example |
|---|---|---|
| Root field | entry field with args | `user(id:1)` |
| Leaf field | scalar inside it | `name` |
| Cycle field | self-referencing edge | `friends` |
| Type name | what the cycle field returns | `User` |

Pull these from introspection, or from InQL's circular-reference output — that's
exactly what it's telling you.

## Scanner

Detects missing cost controls **without applying load**. Every probe resolves to
`__typename` or an introspection meta-field, so it tests the validator rather than the
resolvers -- a 100-alias `__typename` query that returns 200 proves there is no alias
cap while executing no business logic at all. The whole scan is 7 requests and ~87 KB.

| Probe | Detects |
|---|---|
| Introspection | schema exposure, and whether recursive edges are discoverable |
| Alias limiting | no cap on aliased field count |
| Field duplication | duplicates not collapsed before costing |
| Depth limiting | nesting depth unchecked (needs introspection) |
| Batch limiting | array batching enabled |
| Fragment cycle rejection | validator not enforcing the spec rule |
| Request size limiting | no body-size ceiling |

Verdicts are `No limit` / `Limited` / `Inconclusive` / `Error`. Anything ambiguous stays
Inconclusive rather than being guessed -- an unrelated schema error is not evidence of a
limit. **Copy findings** gives you a Markdown table for the report, plus a summary naming
which generator vectors the scan leaves open.

Scan authenticated where the endpoint requires it: limits are frequently applied to
anonymous traffic only.

Two results deserve a second look rather than a tick in the box. A 5xx on a zero-cost
query means something broke without being asked to do any work. And `429` is reported as
`Limited`, but rate limiting is not query-cost limiting -- it does not help when one
request is the attack, so treat it as a separate control.

## Vectors

| Vector | Scales | Tests for |
|---|---|---|
| Alias overload | N aliases | missing `maxAliases` |
| Field duplication | N repeats | dedupe / parse cost |
| Deep nesting | N levels | missing `maxDepth` |
| Circular fragments | N-fragment cycle | validator cycle detection |
| Directive overload | N directives | validator iteration cost |
| Array batching | N operations | missing batch limit |
| Deep introspection | N `ofType` levels | introspection cost |
| Nested + alias | fan-out^N nodes | missing complexity/cost analysis |

**Nested + alias** is the one worth reaching for. Layered fragments keep the request
linear in size while server-side expansion is exponential: at fan-out 2, depth 30,
a 2.2 KB request asks for ~1.07 billion resolver nodes. That request-to-work ratio is
the number to put in a report — it's what makes the issue remotely exploitable by
anyone with a single HTTP client.

Note N means different things per vector: node count for most, *depth* for nested+alias.

## Methodology

The default ramp is geometric (1, 2, 4, 8...) with a 400 ms gap. That's deliberate —
you're looking for the inflection point where response time stops tracking payload
size, and geometric ramping finds it in ~10 requests instead of hundreds. You do not
need to take the service down to prove the vulnerability; an unbounded cost curve
is the proof, and it's far better evidence than an outage you then have to explain.

Guards, all on by default:

- **Scope check** — refuses to fire at anything outside Burp's target scope.
- **Node budget** — confirms before a payload whose estimated server-side node count
  exceeds the budget. Catches the case where fan-out 4 depth 20 looks as harmless as
  fan-out 2 depth 20 but is a million times larger.
- **Abort above ms** / **stop on 5xx** — ends the ramp at the first sign of real
  degradation rather than climbing past it.

Response bodies are grepped for `maxDepth`, `query complexity`, `cost`, `too many` —
a hit in the Note column means a limit is enforced and the vector is closed.

The status line after a run gives you the verdict directly:

```
N 1 -> 512 (512x payload) produced 41 ms -> 9034 ms (220.3x time).
SUPERLINEAR - cost is not bounded, likely missing depth/complexity limiting
```

**Export CSV** gives you the curve for the report. **Send row to Repeater** gives you a
single reproducible request for the PoC section — pick the smallest N that shows clear
degradation, not the largest you fired.

## Reporting

Maps to OWASP API4:2023 Unrestricted Resource Consumption. Typical scoring is
CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High** for an unauthenticated
endpoint; drop to `PR:L` (6.5 Medium) if auth is required. Check whether the program
you're reporting to accepts DoS findings at all — many YesWeHack and HackerOne
programs exclude resource-exhaustion from scope, so confirm before you run the ramp.

Root cause is nearly always the same: the resolver executes before any cost ceiling is
applied. Remediation is depth limiting plus static query cost analysis
(`graphql-depth-limit`, `graphql-cost-analysis`, Apollo's `maxQueryDepth`, or
persisted queries), not rate limiting — rate limits don't help when one request is
the attack.
