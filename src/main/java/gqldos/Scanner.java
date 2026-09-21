package gqldos;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Detects missing query-cost controls without applying load.
 *
 * Every probe resolves to {@code __typename} or an introspection meta-field,
 * which cost the server essentially nothing. What is being measured is whether
 * the validator rejects the shape, not whether the resolvers can survive it.
 * A 100-alias __typename query that returns 200 proves there is no alias cap
 * while executing no business logic at all -- which is both safer against a
 * production target and better report evidence than a timing curve.
 */
public final class Scanner {

    public enum Verdict {
        ABSENT("No limit"),
        PRESENT("Limited"),
        INCONCLUSIVE("Inconclusive"),
        ERROR("Error");

        public final String label;

        Verdict(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public enum Kind {
        INTROSPECTION, ALIAS, DEDUPE, DEPTH, BATCH, FRAGMENT_CYCLE, BODY_SIZE
    }

    public static final class Probe {
        public final Kind kind;
        public final String control;
        public final String body;
        public final String rationale;
        public final boolean needsIntrospection;

        Probe(Kind kind, String control, String body, String rationale, boolean needsIntrospection) {
            this.kind = kind;
            this.control = control;
            this.body = body;
            this.rationale = rationale;
            this.needsIntrospection = needsIntrospection;
        }
    }

    public static final class Finding {
        public final Probe probe;
        public final Verdict verdict;
        public final String evidence;
        public final int status;
        public final long ms;
        public final int reqBytes;

        Finding(Probe probe, Verdict verdict, String evidence, int status, long ms, int reqBytes) {
            this.probe = probe;
            this.verdict = verdict;
            this.evidence = evidence;
            this.status = status;
            this.ms = ms;
            this.reqBytes = reqBytes;
        }
    }

    private static final int ALIAS_N = 100;
    private static final int DEDUPE_N = 100;
    private static final int DEPTH_N = 15;
    private static final int SIZE_N = 5000;

    private Scanner() {
    }

    public static List<Probe> probes() {
        List<Probe> p = new ArrayList<>();

        p.add(new Probe(Kind.INTROSPECTION, "Introspection",
                q("query { __schema { queryType { name } } }"),
                "Open introspection hands an attacker the schema, including any recursive "
                        + "edges that make amplification possible.", false));

        p.add(new Probe(Kind.ALIAS, "Alias limiting",
                q(repeatAliased("__typename", ALIAS_N)),
                ALIAS_N + " aliases of a free meta-field. Accepted means no alias cap; the "
                        + "same shape against a real resolver multiplies its cost.", false));

        p.add(new Probe(Kind.DEDUPE, "Field duplication",
                q("query { " + repeat("__typename ", DEDUPE_N) + "}"),
                DEDUPE_N + " copies of one field. Accepted means duplicates are not collapsed "
                        + "before costing.", false));

        p.add(new Probe(Kind.DEPTH, "Depth limiting",
                q(nestedOfType(DEPTH_N)),
                DEPTH_N + " levels of nesting through the introspection type graph. Depth is "
                        + "checked during validation, so this fires without executing anything.", true));

        p.add(new Probe(Kind.BATCH, "Batch limiting",
                "[{\"query\":\"query { __typename }\"},{\"query\":\"query { __typename }\"}]",
                "Two operations in one request. An array response means batching is on and N "
                        + "operations cost one round trip.", false));

        p.add(new Probe(Kind.FRAGMENT_CYCLE, "Fragment cycle rejection",
                q("fragment A on Query { ...B } fragment B on Query { ...A } query { ...A }"),
                "The spec requires fragment cycles to be rejected. Anything other than a clean "
                        + "validation error points at a validator that can be made to spin.", false));

        p.add(new Probe(Kind.BODY_SIZE, "Request size limiting",
                q(repeatAliased("__typename", SIZE_N)),
                "About 80 KB of zero-cost selections. Accepted means no body-size ceiling, so "
                        + "payload size is not the constraint on how far a vector scales.", false));

        return p;
    }

    /** Classifies one probe response. */
    public static Finding evaluate(Probe p, int status, String resp, long ms) {
        String body = resp == null ? "" : resp;
        String low = body.toLowerCase(Locale.ROOT);
        boolean hasErrors = low.contains("\"errors\"");

        if (status == 0) {
            return f(p, Verdict.ERROR, "no response", status, ms);
        }
        if (status == 429 || low.contains("rate limit") || low.contains("too many requests")) {
            return f(p, Verdict.PRESENT, "rate limited (HTTP " + status + ")", status, ms);
        }
        if (status >= 500) {
            return f(p, Verdict.ERROR, "HTTP " + status + " -- server fault on a zero-cost query "
                    + "is itself worth investigating", status, ms);
        }

        String limitMsg = limitMessage(body);

        switch (p.kind) {
            case INTROSPECTION:
                if (!hasErrors && low.contains("querytype")) {
                    return f(p, Verdict.ABSENT, "introspection enabled", status, ms);
                }
                return f(p, Verdict.PRESENT, limitMsg != null ? limitMsg : "introspection disabled", status, ms);

            case BATCH:
                String t = body.trim();
                if (t.startsWith("[")) {
                    return f(p, Verdict.ABSENT, "array response -- batching enabled", status, ms);
                }
                if (limitMsg != null) {
                    return f(p, Verdict.PRESENT, limitMsg, status, ms);
                }
                return f(p, Verdict.PRESENT, "single response -- batching not honoured", status, ms);

            case FRAGMENT_CYCLE:
                if (!hasErrors) {
                    return f(p, Verdict.ABSENT, "cycle not rejected -- validator does not enforce "
                            + "the spec rule", status, ms);
                }
                if (low.contains("cycle") || low.contains("circular") || low.contains("cannot spread")) {
                    return f(p, Verdict.PRESENT, "cycle rejected at validation", status, ms);
                }
                return f(p, Verdict.INCONCLUSIVE, firstError(body), status, ms);

            case DEPTH:
                if (limitMsg != null) {
                    return f(p, Verdict.PRESENT, limitMsg, status, ms);
                }
                if (!hasErrors) {
                    return f(p, Verdict.ABSENT, "depth " + DEPTH_N + " accepted", status, ms);
                }
                if (low.contains("introspection") && low.contains("disabled")) {
                    return f(p, Verdict.INCONCLUSIVE, "introspection disabled -- depth cannot be "
                            + "probed this way; use a known recursive edge instead", status, ms);
                }
                return f(p, Verdict.INCONCLUSIVE, firstError(body), status, ms);

            default:
                if (limitMsg != null) {
                    return f(p, Verdict.PRESENT, limitMsg, status, ms);
                }
                if (!hasErrors) {
                    return f(p, Verdict.ABSENT, "accepted (HTTP " + status + ")", status, ms);
                }
                return f(p, Verdict.INCONCLUSIVE, firstError(body), status, ms);
        }
    }

    /** Returns a trimmed error message when it names a cost control, else null. */
    private static String limitMessage(String body) {
        String low = body.toLowerCase(Locale.ROOT);
        String[] markers = {
            // depth
            "maxdepth", "max_depth", "too deep", "query depth", "depth limit",
            // cost / complexity (graphql-cost-analysis, Apollo, Stellate)
            "complexity", "cost", "too expensive", "query score",
            // node / breadth caps (Hasura, graphql-armor)
            "node limit", "max node", "too many aliases", "alias limit", "maximum aliases",
            // generic ceilings -- in a GraphQL error these reliably mean a limit fired
            "exceeds", "exceeded", "too many", "limit", "batch", "payload too large",
        };
        for (String m : markers) {
            if (low.contains(m)) {
                return firstError(body);
            }
        }
        return null;
    }

    /** Pulls the first "message" value out of a GraphQL errors array. */
    static String firstError(String body) {
        int k = body.indexOf("\"message\"");
        if (k < 0) {
            return truncate(body, 160);
        }
        int q1 = body.indexOf('"', body.indexOf(':', k) + 1);
        if (q1 < 0) {
            return truncate(body, 160);
        }
        StringBuilder sb = new StringBuilder();
        for (int i = q1 + 1; i < body.length(); i++) {
            char ch = body.charAt(i);
            if (ch == '\\') {
                i++;
                continue;
            }
            if (ch == '"') {
                break;
            }
            sb.append(ch);
        }
        return truncate(sb.toString(), 160);
    }

    /** Which generator vectors the findings leave open. */
    public static String summary(List<Finding> findings) {
        int absent = 0;
        List<String> open = new ArrayList<>();
        boolean introspection = false;
        for (Finding f : findings) {
            if (f.verdict != Verdict.ABSENT) {
                continue;
            }
            absent++;
            switch (f.probe.kind) {
                case ALIAS:          open.add("Alias overload"); break;
                case DEDUPE:         open.add("Field duplication"); break;
                case DEPTH:          open.add("Deep nesting"); break;
                case BATCH:          open.add("Array batching"); break;
                case FRAGMENT_CYCLE: open.add("Circular fragments"); break;
                case INTROSPECTION:  introspection = true; break;
                default: break;
            }
        }
        if (absent == 0) {
            return "No missing controls detected. Every probe was rejected or limited.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(absent).append(" of ").append(findings.size()).append(" controls absent. ");
        if (!open.isEmpty()) {
            sb.append("Vectors open: ").append(String.join(", ", open)).append(". ");
        }
        if (introspection) {
            sb.append("Introspection is open -- check the schema for a self-referencing edge, "
                    + "which is what turns a linear vector into an exponential one.");
        } else {
            sb.append("Introspection is closed, so amplification depends on finding a recursive "
                    + "edge by other means.");
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- builders

    private static String q(String doc) {
        return PayloadFactory.jsonEnvelope(doc, null, null);
    }

    private static String repeatAliased(String field, int n) {
        StringBuilder sb = new StringBuilder("query { ");
        for (int i = 0; i < n; i++) {
            sb.append('p').append(i).append(':').append(field).append(' ');
        }
        return sb.append('}').toString();
    }

    private static String nestedOfType(int depth) {
        StringBuilder sb = new StringBuilder("query { __type(name: \"Query\") { ");
        for (int i = 0; i < depth; i++) {
            sb.append("ofType { ");
        }
        sb.append("name ");
        for (int i = 0; i < depth; i++) {
            sb.append("} ");
        }
        return sb.append("} }").toString();
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static Finding f(Probe p, Verdict v, String evidence, int status, long ms) {
        return new Finding(p, v, evidence, status, ms, p.body.length());
    }

    private static String truncate(String s, int n) {
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= n ? t : t.substring(0, n - 3) + "...";
    }
}
