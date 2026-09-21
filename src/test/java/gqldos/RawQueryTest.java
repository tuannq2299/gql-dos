package gqldos;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RawQueryTest {

    @Test
    void keepsTheOperationHeaderIntact() {
        RawQuery q = RawQuery.parse("query GetUser($id: ID!, $n: Int) { user(id: $id) { name } }");
        assertEquals("query", q.keyword);
        assertEquals("GetUser", q.name);
        assertEquals("query GetUser($id: ID!, $n: Int)", q.header());
    }

    @Test
    void handlesAnonymousShorthand() {
        RawQuery q = RawQuery.parse("{ viewer { id } }");
        assertEquals("query", q.keyword);
        assertEquals("", q.name);
        assertEquals(List.of("viewer { id }"), q.topLevelFields());
    }

    @Test
    void handlesMutations() {
        RawQuery q = RawQuery.parse("mutation Pay($in: PayInput!) { pay(input: $in) { ok } }");
        assertEquals("mutation", q.keyword);
        assertEquals("mutation Pay($in: PayInput!)", q.header());
    }

    @Test
    void splitsTopLevelFieldsWithoutDescendingIntoThem() {
        RawQuery q = RawQuery.parse("query { a { b c } d(x: 1) e }");
        assertEquals(List.of("a { b c }", "d(x: 1)", "e"), q.topLevelFields());
    }

    @Test
    void keepsFragmentDefinitionsAsTrailingText() {
        RawQuery q = RawQuery.parse("query { ...F } fragment F on Query { __typename }");
        assertEquals(List.of("...F"), q.topLevelFields());
        assertTrue(q.trailing.contains("fragment F on Query"), q.trailing);
    }

    @Test
    void aBraceInsideAStringIsNotStructure() {
        RawQuery q = RawQuery.parse("query { search(q: \"a{b}c\") { id } }");
        assertEquals(List.of("search(q: \"a{b}c\") { id }"), q.topLevelFields());
    }

    @Test
    void rejectsAnUnbalancedDocument() {
        assertThrows(IllegalArgumentException.class, () -> RawQuery.parse("query { a "));
    }

    @Test
    void rejectsSomethingThatIsNotAnOperation() {
        assertThrows(IllegalArgumentException.class,
                () -> RawQuery.parse("fragment F on Query { __typename }"));
    }

    // ---------------------------------------------------------- fieldHead

    @Test
    void fieldHeadStripsTheSelectionSet() {
        assertEquals("user(id: $id)", RawQuery.fieldHead("user(id: $id) { name email }"));
    }

    @Test
    void fieldHeadLeavesALeafAlone() {
        assertEquals("name", RawQuery.fieldHead("name"));
    }

    @Test
    void fieldHeadIsNotFooledByABraceInAStringArgument() {
        assertEquals("search(q: \"a{b\")", RawQuery.fieldHead("search(q: \"a{b\") { id }"));
    }

    // -------------------------------------------------------- directives

    @Test
    void directivesGoBeforeTheSelectionSet() {
        assertEquals("user(id: 1) @a @b { name }",
                RawQuery.withDirectives("user(id: 1) { name }", " @a @b"));
    }

    @Test
    void directivesOnALeafAreAppended() {
        assertEquals("name @a", RawQuery.withDirectives("name", " @a"));
    }
}
