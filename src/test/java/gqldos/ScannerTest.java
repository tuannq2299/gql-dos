package gqldos;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScannerTest {

    private static Scanner.Probe probe(Scanner.Kind kind) {
        return probe(Scanner.probes(), kind);
    }

    private static Scanner.Probe probe(List<Scanner.Probe> probes, Scanner.Kind kind) {
        for (Scanner.Probe p : probes) {
            if (p.kind == kind) {
                return p;
            }
        }
        throw new IllegalStateException("no probe for " + kind);
    }

    // ------------------------------------------------- query root type name

    @Test
    void readsANonDefaultRootTypeName() {
        assertEquals("QueryRoot", Scanner.rootTypeFrom(
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"QueryRoot\"}}}}"));
    }

    @Test
    void fallsBackToQueryWhenIntrospectionIsDisabled() {
        assertEquals("Query", Scanner.rootTypeFrom(
                "{\"errors\":[{\"message\":\"introspection is disabled\"}]}"));
    }

    @Test
    void fallsBackToQueryOnJunk() {
        assertEquals("Query", Scanner.rootTypeFrom("not json"));
        assertEquals("Query", Scanner.rootTypeFrom(null));
    }

    @Test
    void refusesAnythingThatIsNotAValidTypeName() {
        // Never splice arbitrary response text into a document.
        assertEquals("Query", Scanner.rootTypeFrom(
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"a b } {\"}}}}"));
    }

    @Test
    void probesAreRebuiltAroundTheReportedRootType() {
        List<Scanner.Probe> probes = Scanner.probes("QueryRoot");
        assertTrue(probe(probes, Scanner.Kind.DEPTH).body
                .contains("__type(name: \\\"QueryRoot\\\")"));
        assertTrue(probe(probes, Scanner.Kind.FRAGMENT_CYCLE).body
                .contains("fragment A on QueryRoot"));
    }

    @Test
    void probeSetIsStableInSizeAndOrderAcrossRootTypes() {
        // The scan rebuilds the list mid-loop and continues by index.
        List<Scanner.Probe> a = Scanner.probes();
        List<Scanner.Probe> b = Scanner.probes("QueryRoot");
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            assertEquals(a.get(i).kind, b.get(i).kind, "probe " + i);
        }
    }

    // ------------------------------------------------------------ verdicts

    @Test
    void acceptedProbeMeansTheControlIsAbsent() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200,
                "{\"data\":{\"p0\":\"Query\",\"p1\":\"Query\"}}", 5);
        assertEquals(Scanner.Verdict.ABSENT, f.verdict);
    }

    @Test
    void aCostErrorMeansTheControlFired() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200,
                "{\"errors\":[{\"message\":\"Query exceeds maximum complexity of 1000\"}]}", 5);
        assertEquals(Scanner.Verdict.PRESENT, f.verdict);
        assertTrue(f.evidence.contains("exceeds maximum complexity"), f.evidence);
    }

    @Test
    void costFiguresInASuccessfulResponseAreNotALimit() {
        // Apollo and Stellate return a cost breakdown in extensions on success.
        // Matching "cost" or "limit" across the whole body reported a control
        // that is not there.
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200,
                "{\"data\":{\"p0\":\"Query\"},"
                + "\"extensions\":{\"cost\":{\"actual\":3,\"limit\":1000}}}", 5);
        assertEquals(Scanner.Verdict.ABSENT, f.verdict);
    }

    @Test
    void anUnrelatedErrorIsNotEvidenceEitherWay() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200,
                "{\"errors\":[{\"message\":\"Cannot query field \\\"nope\\\".\"}]}", 5);
        assertEquals(Scanner.Verdict.INCONCLUSIVE, f.verdict);
    }

    @Test
    void aBlockPageIsNotEvidenceThatTheControlIsAbsent() {
        // The request never reached the resolver. Reporting "No limit" here is
        // the worst outcome the classifier can produce.
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 403,
                "<html>Access denied by security policy</html>", 5);
        assertEquals(Scanner.Verdict.INCONCLUSIVE, f.verdict);
    }

    @Test
    void rateLimitingReportsAsLimited() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 429, "", 5);
        assertEquals(Scanner.Verdict.PRESENT, f.verdict);
    }

    @Test
    void aBodySizeRejectionIsARealControl() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.BODY_SIZE), 413,
                "<html>413 Request Entity Too Large</html>", 5);
        assertEquals(Scanner.Verdict.PRESENT, f.verdict);
    }

    @Test
    void aServerFaultOnAZeroCostProbeIsAnError() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 500, "", 5);
        assertEquals(Scanner.Verdict.ERROR, f.verdict);
    }

    @Test
    void anArrayResponseMeansBatchingIsOn() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.BATCH), 200,
                "[{\"data\":{\"__typename\":\"Query\"}},{\"data\":{\"__typename\":\"Query\"}}]", 5);
        assertEquals(Scanner.Verdict.ABSENT, f.verdict);
    }

    @Test
    void aRejectedCycleIsTheCompliantOutcome() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.FRAGMENT_CYCLE), 200,
                "{\"errors\":[{\"message\":\"Cannot spread fragment A within itself.\"}]}", 5);
        assertEquals(Scanner.Verdict.PRESENT, f.verdict);
    }

    @Test
    void introspectionVerdictNamesTheRootType() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.INTROSPECTION), 200,
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"QueryRoot\"}}}}", 5);
        assertEquals(Scanner.Verdict.ABSENT, f.verdict);
        assertTrue(f.evidence.contains("QueryRoot"), f.evidence);
    }

    // ------------------------------------------------- the hung-cycle case

    @Test
    void anUnansweredCycleIsRecognised() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.FRAGMENT_CYCLE), 0, "", 30_000);
        assertEquals(Scanner.Verdict.ERROR, f.verdict);
        assertTrue(Scanner.cycleUnanswered(f));
    }

    @Test
    void anUnansweredCycleReachesTheSummary() {
        // A validator spinning on a cycle is the strongest result the scan can
        // produce, and it never classifies as ABSENT, so counting only ABSENT
        // dropped it entirely.
        List<Scanner.Finding> findings = new ArrayList<>();
        findings.add(Scanner.evaluate(probe(Scanner.Kind.FRAGMENT_CYCLE), 0, "", 30_000));
        String summary = Scanner.summary(findings);
        assertTrue(summary.contains("Circular fragments"), summary);
        assertFalse(summary.contains("No missing controls detected"), summary);
    }

    @Test
    void aTimeoutOnAnotherProbeIsNotTreatedAsAHungCycle() {
        Scanner.Finding f = Scanner.evaluate(probe(Scanner.Kind.ALIAS), 0, "", 30_000);
        assertFalse(Scanner.cycleUnanswered(f));
    }

    @Test
    void aFullyLimitedEndpointSaysSo() {
        List<Scanner.Finding> findings = new ArrayList<>();
        findings.add(Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200,
                "{\"errors\":[{\"message\":\"too many aliases\"}]}", 5));
        assertTrue(Scanner.summary(findings).contains("No missing controls detected"));
    }

    @Test
    void summaryNamesTheGeneratorVectorsLeftOpen() {
        List<Scanner.Finding> findings = new ArrayList<>();
        findings.add(Scanner.evaluate(probe(Scanner.Kind.ALIAS), 200, "{\"data\":{}}", 5));
        findings.add(Scanner.evaluate(probe(Scanner.Kind.BATCH), 200, "[{\"data\":{}}]", 5));
        String summary = Scanner.summary(findings);
        assertTrue(summary.contains("Alias overload"), summary);
        assertTrue(summary.contains("Array batching"), summary);
    }

    // -------------------------------------------------- message extraction

    @Test
    void collectsEveryErrorMessage() {
        List<String> messages = Scanner.errorMessages(
                "{\"errors\":[{\"message\":\"a \\\"quoted\\\" thing\"},{\"message\":\"second\"}]}");
        assertEquals(2, messages.size(), String.valueOf(messages));
    }

    @Test
    void survivesATruncatedResponse() {
        // A half-received body must terminate, not spin.
        assertTrue(Scanner.errorMessages("{\"errors\":[{\"message\":\"unterminated").size() <= 1);
    }

    @Test
    void ignoresANonStringMessage() {
        assertTrue(Scanner.errorMessages("{\"message\":42}").isEmpty());
    }

    // -------------------------------------------------------- probe bodies

    @Test
    void everyProbeIsSmallAndSelectsNoBusinessField() {
        for (Scanner.Probe p : Scanner.probes()) {
            assertTrue(p.body.length() < 120_000, p.control + " is " + p.body.length() + " bytes");
            assertTrue(p.body.contains("__typename") || p.body.contains("__schema")
                            || p.body.contains("__type") || p.kind == Scanner.Kind.FRAGMENT_CYCLE,
                    p.control + " selects something other than a meta-field: " + p.body);
        }
    }

    @Test
    void theWholeScanStaysUnderAHundredKilobytes() {
        int total = 0;
        for (Scanner.Probe p : Scanner.probes()) {
            total += p.body.length();
        }
        assertTrue(total < 100_000, "scan sends " + total + " bytes");
    }
}
