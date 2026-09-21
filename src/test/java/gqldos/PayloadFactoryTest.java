package gqldos;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PayloadFactoryTest {

    /** A realistic captured body: envelope, operation name, variables. */
    private static final String CAPTURED =
            "{\"operationName\":\"GetUser\",\"variables\":{\"id\":\"7\"},"
            + "\"query\":\"query GetUser($id: ID!) { user(id: $id) { name email } }\"}";

    private static PayloadFactory.Config captured() {
        PayloadFactory.Config c = new PayloadFactory.Config();
        c.requestBody = CAPTURED;
        c.cycleField = "friends";
        c.typeName = "User";
        c.leafField = "name";
        return c;
    }

    // ------------------------------------------------------------ envelope

    @Test
    void aliasOverloadPreservesTheEnvelope() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, captured(), 3);
        assertTrue(out.contains("\"operationName\":\"GetUser\""), out);
        assertTrue(out.contains("\"variables\":{\"id\":\"7\"}"), out);
        assertTrue(out.contains("query GetUser($id: ID!)"), out);
    }

    @Test
    void aliasOverloadMultipliesExactlyN() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, captured(), 3);
        assertTrue(out.contains("a0: user"), out);
        assertTrue(out.contains("a2: user"), out);
        assertFalse(out.contains("a3:"), out);
    }

    @Test
    void arrayBatchRepeatsTheWholeRequest() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ARRAY_BATCH, captured(), 4);
        assertTrue(out.startsWith("["), out);
        assertEquals(4, countOf(out, "\"operationName\":\"GetUser\""), out);
    }

    // ------------------------------------- recursion vectors, captured mode

    @Test
    void deepNestingWorksFromACapturedRequest() {
        String out = PayloadFactory.body(PayloadFactory.Vector.DEEP_NESTING, captured(), 4);
        assertEquals(4, countOf(out, "friends {"), out);
        assertTrue(out.contains("\"variables\":{\"id\":\"7\"}"), out);
        assertTrue(out.contains("user(id: $id)"), out);
        assertTrue(balanced(document(out)), out);
    }

    @Test
    void deepNestingDropsTheCapturedSelectionSet() {
        // The captured query selected name and email. Keeping them alongside a
        // replacement selection set would not parse.
        String out = PayloadFactory.body(PayloadFactory.Vector.DEEP_NESTING, captured(), 2);
        assertFalse(out.contains("email"), out);
    }

    @Test
    void circularFragmentClosesTheCycle() {
        String out = PayloadFactory.body(PayloadFactory.Vector.CIRCULAR_FRAGMENT, captured(), 3);
        assertTrue(out.contains("fragment f0 on User"), out);
        assertTrue(out.contains("fragment f2 on User"), out);
        assertFalse(out.contains("fragment f3"), out);
        assertTrue(out.contains("fragment f2 on User { friends { ...f0 } }"), out);
        assertTrue(balanced(document(out)), out);
    }

    @Test
    void nestedAliasStaysLinearInSizeWhileExpansionIsExponential() {
        PayloadFactory.Config c = captured();
        c.breadth = 2;
        String out = PayloadFactory.body(PayloadFactory.Vector.NESTED_ALIAS, c, 5);
        assertTrue(out.contains("fragment L0 on User"), out);
        assertTrue(out.contains("fragment L5 on User"), out);
        assertFalse(out.contains("fragment L6"), out);
        assertEquals(5, countOf(out, "b1: friends"), out);
        assertTrue(out.length() < 1200, "request should stay small: " + out.length());
        assertEquals(32, PayloadFactory.estimatedNodes(PayloadFactory.Vector.NESTED_ALIAS, c, 5));
        assertTrue(balanced(document(out)), out);
    }

    // ------------------------------------------------------------- guards

    @Test
    void missingCycleFieldNamesTheFieldToFillIn() {
        PayloadFactory.Config c = captured();
        c.cycleField = "";
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> PayloadFactory.body(PayloadFactory.Vector.DEEP_NESTING, c, 3));
        assertTrue(e.getMessage().contains("Cycle field"), e.getMessage());
    }

    @Test
    void missingCycleFieldDoesNotClaimSomethingAboutTheSchema() {
        // The old message asserted the schema had no recursive edge, which the
        // code never checked.
        PayloadFactory.Config c = captured();
        c.cycleField = "";
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> PayloadFactory.body(PayloadFactory.Vector.NESTED_ALIAS, c, 3));
        assertFalse(e.getMessage().contains("does not apply to this schema"), e.getMessage());
    }

    @Test
    void fragmentVectorsAlsoNeedTheTypeName() {
        PayloadFactory.Config c = captured();
        c.typeName = "";
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> PayloadFactory.body(PayloadFactory.Vector.CIRCULAR_FRAGMENT, c, 3));
        assertTrue(e.getMessage().contains("Type name"), e.getMessage());
    }

    @Test
    void sizeCeilingRefusesBeforeAllocating() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, captured(), 1_000_000));
        assertTrue(e.getMessage().contains("ceiling"), e.getMessage());
    }

    @Test
    void sizeCeilingStillAllowsUsefulSizes() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, captured(), 10_000);
        assertTrue(out.length() > 100_000, "len=" + out.length());
        assertTrue(out.length() < PayloadFactory.MAX_PAYLOAD_BYTES, "len=" + out.length());
    }

    @Test
    void estimateTracksTheRealSizeCloselyEnoughToGuard() {
        PayloadFactory.Config c = captured();
        long estimate = PayloadFactory.estimatedBytes(PayloadFactory.Vector.ALIAS_OVERLOAD, c, 500);
        long actual = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, c, 500).length();
        assertTrue(estimate >= actual * 0.5 && estimate <= actual * 2.0,
                "estimate=" + estimate + " actual=" + actual);
    }

    // -------------------------------------------------------- schema mode

    @Test
    void schemaModeBuildsFromTheFormAlone() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD,
                new PayloadFactory.Config(), 2);
        assertTrue(out.contains("a0: user(id:1) { name }"), out);
    }

    @Test
    void generatedOperationNameDoesNotAnnounceTheTest() {
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD,
                new PayloadFactory.Config(), 2);
        assertFalse(out.contains("DoS"), out);
    }

    @Test
    void aliasPrefixIsSanitisedIntoAValidName() {
        PayloadFactory.Config c = new PayloadFactory.Config();
        c.aliasPrefix = "9-x";
        String out = PayloadFactory.body(PayloadFactory.Vector.ALIAS_OVERLOAD, c, 1);
        // Must not start with a digit, and the hyphen is not a name character.
        assertTrue(out.contains("a9_x0:"), out);
    }

    // ------------------------------------------------------------ helpers

    private static int countOf(String s, String sub) {
        int n = 0;
        int i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) {
            n++;
            i += sub.length();
        }
        return n;
    }

    /** Pulls the GraphQL document back out of the JSON envelope. */
    private static String document(String json) {
        int k = json.indexOf("\"query\":\"");
        if (k < 0) {
            return json;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = k + 9; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (ch == '\\') {
                i++;
                sb.append(' ');
                continue;
            }
            if (ch == '"') {
                break;
            }
            sb.append(ch);
        }
        return sb.toString();
    }

    private static boolean balanced(String doc) {
        int depth = 0;
        for (int i = 0; i < doc.length(); i++) {
            char ch = doc.charAt(i);
            if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth < 0) {
                    return false;
                }
            }
        }
        return depth == 0;
    }
}
