package gqldos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/** Runs the control probes and reports which cost limits are missing. */
public class ScanPanel extends JPanel {

    private final MontoyaApi api;
    private final AtomicBoolean stopFlag = new AtomicBoolean(false);
    /** The in-flight scan, so it can be stopped when the extension unloads. */
    private volatile Thread worker;

    private final JTextField urlField = new JTextField("https://target/graphql", 40);
    private final JTextArea headersArea = new JTextArea(3, 40);
    private final JCheckBox scopeBox = new JCheckBox("Require target in Burp scope", true);
    private final JSpinner delaySpin = new JSpinner(new SpinnerNumberModel(300, 0, 10_000, 50));

    private final DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Control", "Verdict", "Evidence", "HTTP", "ms", "Req bytes"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    };
    private final JTable table = new JTable(model);
    private final JTextArea rationale = new JTextArea(4, 70);

    private final JButton scanBtn = new JButton("Run scan");
    private final JButton stopBtn = new JButton("Stop");
    private final JButton copyBtn = new JButton("Copy findings");
    private final JLabel status = new JLabel("Idle. Probes resolve only __typename and introspection "
            + "meta-fields, so they cost the server nothing.");

    /** Written by the scan thread, read on the EDT. */
    private final List<Scanner.Finding> findings = new CopyOnWriteArrayList<>();

    public ScanPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        add(buildForm(), BorderLayout.NORTH);
        add(buildResults(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        scanBtn.addActionListener(e -> start());
        stopBtn.addActionListener(e -> stopFlag.set(true));
        copyBtn.addActionListener(e -> copyFindings());
        stopBtn.setEnabled(false);
        table.getSelectionModel().addListSelectionListener(e -> showRationale());
    }

    /**
     * Stops the scan thread. Called from the extension's unloading handler:
     * a daemon thread is not enough, because Burp keeps running after an
     * unload and an in-flight scan would go on hitting the target with no UI
     * left to stop it from.
     */
    public void shutdown() {
        stopFlag.set(true);
        Thread t = worker;
        if (t != null) {
            t.interrupt();
        }
    }

    private JComponent buildForm() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("Target"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("Endpoint URL"), g);
        g.gridx = 1; g.gridwidth = 3; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        p.add(urlField, g);
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;

        g.gridx = 0; g.gridy = 1; p.add(new JLabel("Extra headers"), g);
        headersArea.setToolTipText("One per line. Scan authenticated where the endpoint requires it -- "
                + "limits are often only applied to anonymous traffic.");
        g.gridx = 1; g.gridwidth = 3; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        p.add(new JScrollPane(headersArea), g);
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;

        g.gridx = 0; g.gridy = 2; p.add(new JLabel("Options"), g);
        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        opts.add(scopeBox);
        opts.add(new JLabel("delay ms"));
        opts.add(delaySpin);
        g.gridx = 1; g.gridwidth = 3;
        p.add(opts, g);
        return p;
    }

    private JComponent buildResults() {
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(2).setPreferredWidth(420);
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                    boolean foc, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, v, sel, foc, row, col);
                String s = String.valueOf(v);
                if (!sel) {
                    // Resolved per paint, not cached: the user can switch Burp
                    // between the light and dark themes while we are loaded.
                    if (Scanner.Verdict.ABSENT.label.equals(s)) {
                        c.setForeground(Ui.bad(api));
                    } else if (Scanner.Verdict.PRESENT.label.equals(s)) {
                        c.setForeground(Ui.good(api));
                    } else {
                        c.setForeground(Ui.hint(api));
                    }
                }
                return c;
            }
        });

        rationale.setEditable(false);
        rationale.setLineWrap(true);
        rationale.setWrapStyleWord(true);
        rationale.setBorder(BorderFactory.createTitledBorder("Why this probe"));

        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(rationale));
        sp.setResizeWeight(0.75);
        return sp;
    }

    private JComponent buildFooter() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(scanBtn);
        buttons.add(stopBtn);
        buttons.add(copyBtn);
        p.add(buttons, BorderLayout.WEST);
        status.setForeground(Ui.hint(api));
        p.add(status, BorderLayout.SOUTH);
        return p;
    }

    /** Called from the context menu when a request is imported from Burp. */
    public void loadFrom(HttpRequest req) {
        SwingUtilities.invokeLater(() -> {
            urlField.setText(req.url());
            StringBuilder sb = new StringBuilder();
            req.headers().forEach(h -> {
                String n = h.name();
                if (n.equalsIgnoreCase("Authorization")
                        || n.equalsIgnoreCase("Cookie")
                        || n.equalsIgnoreCase("X-Api-Key")
                        || n.toLowerCase().startsWith("x-")) {
                    sb.append(n).append(": ").append(h.value()).append('\n');
                }
            });
            headersArea.setText(sb.toString().trim());
        });
    }

    private void showRationale() {
        int row = table.getSelectedRow();
        if (row < 0) {
            rationale.setText("");
            return;
        }
        int idx = table.convertRowIndexToModel(row);
        if (idx < 0 || idx >= findings.size()) {
            rationale.setText("");
            return;
        }
        Scanner.Finding f = findings.get(idx);
        rationale.setText(f.probe.rationale + "\n\nPayload: " + f.probe.body);
        rationale.setCaretPosition(0);
    }

    private void start() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            status.setText("Set an endpoint URL first.");
            return;
        }
        if (scopeBox.isSelected() && !api.scope().isInScope(url)) {
            status.setText("Blocked: " + url + " is not in Burp scope.");
            return;
        }

        model.setRowCount(0);
        findings.clear();
        rationale.setText("");
        stopFlag.set(false);
        scanBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        status.setForeground(Ui.hint(api));
        long delay = ((Integer) delaySpin.getValue()).longValue();

        Thread t = new Thread(() -> {
            try {
                List<Scanner.Probe> probes = Scanner.probes();
                for (int i = 0; i < probes.size(); i++) {
                    if (stopFlag.get() || Thread.currentThread().isInterrupted()) {
                        setStatus("Stopped.");
                        return;
                    }
                    Scanner.Probe probe = probes.get(i);
                    long t0 = System.nanoTime();
                    int code = 0;
                    String respBody = "";
                    try {
                        HttpRequestResponse rr = api.http().sendRequest(buildRequest(url, probe.body));
                        if (rr.response() != null) {
                            code = rr.response().statusCode();
                            respBody = rr.response().bodyToString();
                        }
                    } catch (Exception ex) {
                        respBody = "";
                    }
                    long ms = (System.nanoTime() - t0) / 1_000_000L;

                    Scanner.Finding f = Scanner.evaluate(probe, code, respBody, ms);
                    findings.add(f);
                    SwingUtilities.invokeLater(() -> model.addRow(new Object[]{
                            f.probe.control, f.verdict.label, f.evidence,
                            f.status == 0 ? "-" : String.valueOf(f.status), f.ms, f.reqBytes}));

                    // The introspection probe asked the server for its query
                    // root type name. Rebuild the remaining probes around the
                    // answer: depth and fragment-cycle both name that type, and
                    // a guess of "Query" against a QueryRoot schema tests
                    // nothing while reporting Inconclusive.
                    if (probe.kind == Scanner.Kind.INTROSPECTION) {
                        String root = Scanner.rootTypeFrom(respBody);
                        if (!Scanner.DEFAULT_ROOT_TYPE.equals(root)) {
                            probes = Scanner.probes(root);
                            setStatus("Query root type is '" + root + "'; remaining probes "
                                    + "rebuilt against it.");
                        }
                    }

                    if (delay > 0) {
                        Thread.sleep(delay);
                    }
                }
                setStatus(Scanner.summary(findings));
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                setStatus("Stopped.");
            } finally {
                worker = null;
                SwingUtilities.invokeLater(() -> {
                    scanBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                });
            }
        }, "gql-dos-scanner");
        t.setDaemon(true);
        worker = t;
        t.start();
    }

    private HttpRequest buildRequest(String url, String body) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json")
                .withBody(body);
        for (String line : headersArea.getText().split("\\R")) {
            int i = line.indexOf(':');
            if (i > 0) {
                req = req.withHeader(line.substring(0, i).trim(), line.substring(i + 1).trim());
            }
        }
        return req;
    }

    private void copyFindings() {
        if (findings.isEmpty()) {
            status.setText("Nothing to copy. Run a scan first.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("GraphQL cost-control scan -- ").append(urlField.getText().trim()).append("\n\n");
        sb.append("| Control | Verdict | Evidence |\n|---|---|---|\n");
        for (Scanner.Finding f : findings) {
            sb.append("| ").append(f.probe.control)
              .append(" | ").append(f.verdict.label)
              .append(" | ").append(f.evidence.replace("|", "\\|")).append(" |\n");
        }
        sb.append('\n').append(Scanner.summary(findings)).append('\n');
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        status.setText("Findings copied as a Markdown table.");
    }

    private void setStatus(String s) {
        SwingUtilities.invokeLater(() -> status.setText(s));
    }
}
