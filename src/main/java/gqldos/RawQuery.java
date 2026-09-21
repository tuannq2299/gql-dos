package gqldos;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal structural parser for a real GraphQL operation.
 *
 * Enough to take an operation captured from traffic, keep its variable
 * definitions intact, and multiply its top-level field selections. Not a
 * full GraphQL parser -- it does not validate, it only finds boundaries.
 */
public final class RawQuery {

    public String keyword = "query";   // query | mutation | subscription
    public String name = "";           // operation name, may be empty
    public String varDefs = "";        // "($a: A!, $b: B)" including parens, or ""
    public String body = "";           // inner selection set, outer braces stripped
    public String trailing = "";       // fragment definitions outside the operation

    private RawQuery() {
    }

    public static RawQuery parse(String src) {
        RawQuery q = new RawQuery();
        String s = src == null ? "" : src.trim();
        if (s.isEmpty()) {
            throw new IllegalArgumentException("empty query");
        }

        int opStart = findOperation(s);
        if (opStart < 0) {
            throw new IllegalArgumentException("no query/mutation/subscription operation found");
        }

        int i = opStart;
        if (s.charAt(i) == '{') {
            // anonymous shorthand: { field }
            q.keyword = "query";
        } else {
            int kwEnd = readName(s, i);
            q.keyword = s.substring(i, kwEnd);
            i = skipWs(s, kwEnd);
            if (i < s.length() && isNameStart(s.charAt(i))) {
                int nameEnd = readName(s, i);
                q.name = s.substring(i, nameEnd);
                i = skipWs(s, nameEnd);
            }
            if (i < s.length() && s.charAt(i) == '(') {
                int close = matchDelim(s, i, '(', ')');
                q.varDefs = s.substring(i, close);
                i = skipWs(s, close);
            }
        }

        if (i >= s.length() || s.charAt(i) != '{') {
            throw new IllegalArgumentException("expected '{' after operation header");
        }
        int bodyEnd = matchDelim(s, i, '{', '}');
        q.body = s.substring(i + 1, bodyEnd - 1).trim();

        String before = s.substring(0, opStart).trim();
        String after = s.substring(bodyEnd).trim();
        q.trailing = (before + "\n" + after).trim();
        return q;
    }

    /** Operation header as written, e.g. {@code query getX($a: A!)}. */
    public String header() {
        StringBuilder sb = new StringBuilder(keyword);
        if (!name.isEmpty()) {
            sb.append(' ').append(name);
        }
        if (!varDefs.isEmpty()) {
            sb.append(varDefs);
        }
        return sb.toString();
    }

    /** Header with a caller-supplied operation name, variable defs preserved. */
    public String header(String newName) {
        StringBuilder sb = new StringBuilder(keyword);
        if (newName != null && !newName.isEmpty()) {
            sb.append(' ').append(newName);
        }
        if (!varDefs.isEmpty()) {
            sb.append(varDefs);
        }
        return sb.toString();
    }

    /** Splits the body into its top-level field selections. */
    public List<String> topLevelFields() {
        List<String> out = new ArrayList<>();
        String b = body;
        int i = 0;
        int n = b.length();
        while (i < n) {
            i = skipWs(b, i);
            if (i >= n) {
                break;
            }
            int start = i;

            if (b.startsWith("...", i)) {
                i += 3;
                i = skipWs(b, i);
                if (b.startsWith("on", i)) {
                    i = readName(b, i);
                    i = skipWs(b, i);
                    i = readName(b, i);
                } else if (i < n && isNameStart(b.charAt(i))) {
                    i = readName(b, i);
                }
                i = skipWs(b, i);
                if (i < n && b.charAt(i) == '{') {
                    i = matchDelim(b, i, '{', '}');
                }
                out.add(b.substring(start, i).trim());
                continue;
            }

            i = readName(b, i);
            int j = skipWs(b, i);
            if (j < n && b.charAt(j) == ':') {              // alias
                j = skipWs(b, j + 1);
                i = readName(b, j);
            }
            j = skipWs(b, i);
            if (j < n && b.charAt(j) == '(') {              // arguments
                i = matchDelim(b, j, '(', ')');
            }
            while (true) {                                   // directives
                j = skipWs(b, i);
                if (j < n && b.charAt(j) == '@') {
                    i = readName(b, j + 1);
                    int k = skipWs(b, i);
                    if (k < n && b.charAt(k) == '(') {
                        i = matchDelim(b, k, '(', ')');
                    }
                } else {
                    break;
                }
            }
            j = skipWs(b, i);
            if (j < n && b.charAt(j) == '{') {              // selection set
                i = matchDelim(b, j, '{', '}');
            }
            String field = b.substring(start, i).trim();
            if (!field.isEmpty()) {
                out.add(field);
            }
        }
        return out;
    }

    /**
     * Inserts directives into a field, before its selection set if it has one.
     * Used by the directive-overload vector on a real captured field.
     */
    public static String withDirectives(String field, String directives) {
        int brace = -1;
        int depth = 0;
        boolean inStr = false;
        for (int i = 0; i < field.length(); i++) {
            char ch = field.charAt(i);
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
            } else if (ch == '(' || ch == '[') {
                depth++;
            } else if (ch == ')' || ch == ']') {
                depth--;
            } else if (ch == '{' && depth == 0) {
                brace = i;
                break;
            }
        }
        return brace < 0
                ? field + " " + directives
                : field.substring(0, brace) + directives + " " + field.substring(brace);
    }

    // ------------------------------------------------------------------ lexing

    private static int findOperation(String s) {
        int depth = 0;
        boolean inStr = false;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
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
                continue;
            }
            if (ch == '{') {
                if (depth == 0 && !precededByFragment(s, i)) {
                    return i;   // anonymous shorthand
                }
                depth++;
                continue;
            }
            if (ch == '}') {
                depth--;
                continue;
            }
            if (depth == 0 && isNameStart(ch) && (i == 0 || !isNameChar(s.charAt(i - 1)))) {
                int end = readName(s, i);
                String w = s.substring(i, end);
                if (w.equals("query") || w.equals("mutation") || w.equals("subscription")) {
                    return i;
                }
                i = end - 1;
            }
        }
        return -1;
    }

    private static boolean precededByFragment(String s, int braceIdx) {
        int i = braceIdx - 1;
        while (i >= 0 && Character.isWhitespace(s.charAt(i))) {
            i--;
        }
        int end = i + 1;
        while (i >= 0 && isNameChar(s.charAt(i))) {
            i--;
        }
        String word = s.substring(i + 1, end);
        if (word.isEmpty()) {
            return false;
        }
        int k = i;
        while (k >= 0 && Character.isWhitespace(s.charAt(k))) {
            k--;
        }
        int e2 = k + 1;
        while (k >= 0 && isNameChar(s.charAt(k))) {
            k--;
        }
        return s.substring(k + 1, e2).equals("on");
    }

    private static int matchDelim(String s, int open, char o, char c) {
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < s.length(); i++) {
            char ch = s.charAt(i);
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
            } else if (ch == o) {
                depth++;
            } else if (ch == c) {
                depth--;
                if (depth == 0) {
                    return i + 1;
                }
            }
        }
        throw new IllegalArgumentException("unbalanced '" + o + "' at offset " + open);
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) {
            i++;
        }
        return i;
    }

    private static int readName(String s, int i) {
        int j = i;
        while (j < s.length() && isNameChar(s.charAt(j))) {
            j++;
        }
        return j == i ? i + 1 : j;
    }

    private static boolean isNameStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
}
