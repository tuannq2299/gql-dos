package gqldos;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Collections;
import java.util.List;

/**
 * Turns scan findings into Burp audit issues.
 *
 * A finding that only exists in this extension's own table is a finding the
 * rest of the workflow cannot see: it misses the Issues view, the report
 * export and anything reading the site map. Only findings that say something
 * is missing become issues -- a control that fired is not a vulnerability, and
 * filing it would bury the ones that matter.
 */
final class Issues {

    private static final String BACKGROUND =
            "A GraphQL endpoint costs a query by executing it. Where the server applies no "
            + "ceiling before execution, the work it performs is controlled by the client: "
            + "aliases, duplicated fields, nesting and batching each multiply resolver calls "
            + "without a matching increase in request size. This maps to OWASP "
            + "API4:2023 Unrestricted Resource Consumption.\n\n"
            + "This issue was raised by a probe that selects only __typename or an "
            + "introspection meta-field, so the endpoint was asked to do no business work. "
            + "What it demonstrates is that the validator accepts the shape, not that the "
            + "service has been degraded. Establishing impact means resending the shape "
            + "against a real field at increasing sizes and timing the responses.";

    private static final String REMEDIATION_BACKGROUND =
            "Cost controls belong in validation, before any resolver runs. Static query cost "
            + "analysis with a per-query budget covers the whole class; depth limiting alone "
            + "covers only nesting. Persisted queries remove the problem entirely where the "
            + "client set is closed.\n\n"
            + "Rate limiting is not a substitute. It bounds requests per interval, and one "
            + "request is enough here.";

    private Issues() {
    }

    /**
     * Builds the issue for a finding, or null when the finding is not one.
     *
     * @param exchange the probe's request and response, attached as evidence;
     *                 may be null when the request never completed
     */
    static AuditIssue from(Scanner.Finding f, String url, HttpRequestResponse exchange) {
        boolean hung = Scanner.cycleUnanswered(f);
        if (!hung && f.verdict != Scanner.Verdict.ABSENT) {
            return null;
        }

        List<HttpRequestResponse> evidence = exchange == null
                ? Collections.emptyList() : Collections.singletonList(exchange);

        if (hung) {
            return AuditIssue.auditIssue(
                    "GraphQL fragment cycle not answered",
                    detail(f, "The endpoint neither rejected the cycle nor returned a response. "
                            + "A validator that does neither is still walking the cycle. The "
                            + "request carries no authentication requirement, asks for no "
                            + "resolver work and is roughly 200 bytes."),
                    "Reject fragment cycles during validation, as required by the GraphQL "
                            + "specification (section 5.5.2.2, 'Fragment spreads must not form "
                            + "cycles'). Any validator reaching this state has a reachable "
                            + "non-terminating path.",
                    url,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.TENTATIVE,
                    BACKGROUND,
                    REMEDIATION_BACKGROUND,
                    AuditIssueSeverity.HIGH,
                    evidence);
        }

        return AuditIssue.auditIssue(
                "GraphQL cost control missing: " + f.probe.control,
                detail(f, f.probe.rationale),
                remediation(f.probe.kind),
                url,
                severity(f.probe.kind),
                AuditIssueConfidence.FIRM,
                BACKGROUND,
                REMEDIATION_BACKGROUND,
                severity(f.probe.kind),
                evidence);
    }

    private static String detail(Scanner.Finding f, String rationale) {
        return "<p>" + escape(rationale) + "</p>"
                + "<p><b>Result:</b> " + escape(f.verdict.label)
                + " &mdash; " + escape(f.evidence)
                + " (HTTP " + (f.status == 0 ? "no response" : String.valueOf(f.status))
                + ", " + f.ms + " ms, " + f.reqBytes + " request bytes).</p>"
                + "<p><b>Probe sent:</b></p><pre>" + escape(f.probe.body) + "</pre>";
    }

    private static AuditIssueSeverity severity(Scanner.Kind kind) {
        switch (kind) {
            // Readable schema is a prerequisite for the rest, not resource
            // consumption on its own.
            case INTROSPECTION:
                return AuditIssueSeverity.INFORMATION;
            // Batching multiplies every other vector by N in one round trip.
            case BATCH:
            case DEPTH:
                return AuditIssueSeverity.MEDIUM;
            default:
                return AuditIssueSeverity.LOW;
        }
    }

    private static String remediation(Scanner.Kind kind) {
        switch (kind) {
            case INTROSPECTION:
                return "Disable introspection in production. This does not remove the "
                        + "underlying cost problem -- a recursive edge is still reachable by "
                        + "anyone who knows the schema -- so treat it as reducing discovery, "
                        + "not as a fix.";
            case ALIAS:
                return "Cap the number of aliased fields per operation, or better, adopt "
                        + "static query cost analysis that prices each selection. Alias "
                        + "caps alone are bypassed by nesting.";
            case DEDUPE:
                return "Collapse duplicate selections before costing the query, or price "
                        + "each occurrence.";
            case DEPTH:
                return "Apply a depth limit during validation (graphql-depth-limit, Apollo "
                        + "maxQueryDepth, or equivalent). Choose the limit from the deepest "
                        + "query the real clients send, not from a round number.";
            case BATCH:
                return "Cap operations per batch, or disable array batching where clients "
                        + "do not use it. Batching multiplies every other vector by N in a "
                        + "single round trip, so a cost budget must be applied across the "
                        + "whole batch rather than per operation.";
            case FRAGMENT_CYCLE:
                return "Reject fragment cycles during validation, as required by the GraphQL "
                        + "specification (section 5.5.2.2).";
            case BODY_SIZE:
                return "Set a request body size limit at the proxy or application server. "
                        + "This bounds how far the other vectors scale; it does not replace "
                        + "query cost analysis, since a small request can still be expensive.";
            default:
                return "Apply static query cost analysis before execution.";
        }
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
