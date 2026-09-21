package gqldos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * Payload generator. Builds a GraphQL resource-consumption payload at a
 * chosen size and hands it to Repeater or the clipboard. It never sends a
 * request itself -- firing stays a deliberate act in Repeater.
 */
public class DosPanel extends JPanel {

    /**
     * How much of the payload is rendered in the preview box. A JTextArea holding
     * megabytes of text is slow to lay out and scroll, and nothing is learned from
     * the four hundred thousandth alias. The full payload is what reaches the
     * clipboard and Repeater.
     */
    private static final int PREVIEW_LIMIT = 512 * 1024;

    private final MontoyaApi api;
    private final PayloadFactory.Config cfg = new PayloadFactory.Config();

    private final JTextField urlField = new JTextField("https://target/graphql", 40);
    private final JTextArea headersArea = new JTextArea(3, 40);

    private final JComboBox<PayloadFactory.Vector> vectorBox =
            new JComboBox<>(PayloadFactory.Vector.values());
    private final JLabel vectorHelp = new JLabel(" ");
    private final JTextField aliasPrefixField = new JTextField("a", 8);
    private final JSpinner countSpin = new JSpinner(new SpinnerNumberModel(100, 1, 1_000_000, 1));

    private final JTabbedPane modeTabs = new JTabbedPane();
    private final JTextArea requestBodyArea = new JTextArea(12, 70);

    private final JTextField rootFieldField = new JTextField(cfg.rootField, 22);
    private final JTextField leafFieldField = new JTextField(cfg.leafField, 14);
    private final JTextField cycleFieldField = new JTextField(cfg.cycleField, 14);
    private final JTextField typeNameField = new JTextField(cfg.typeName, 14);
    private final JSpinner breadthSpin = new JSpinner(new SpinnerNumberModel(2, 2, 16, 1));

    private final JTextArea output = new JTextArea(14, 70);
    private final JButton generateBtn = new JButton("Generate payload");
    private final JButton copyBtn = new JButton("Copy to clipboard");
    private final JButton repeaterBtn = new JButton("Send to Repeater");
    private final JLabel status = new JLabel("Idle.");

    /** The built payload in full; the preview box may hold a truncated copy. */
    private volatile String payload = "";
    /** The in-flight build, so it can be cancelled when the extension unloads. */
    private volatile SwingWorker<String, Void> worker;

    public DosPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildForm(), buildOutput());
        split.setResizeWeight(0.55);
        add(split, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        vectorBox.addActionListener(e -> {
            updateVectorHelp();
            invalidatePayload();
        });
        countSpin.addChangeListener(e -> invalidatePayload());
        breadthSpin.addChangeListener(e -> invalidatePayload());
        // Any change to the inputs makes a previously built payload stale, so
        // Copy and Send to Repeater cannot hand out something the form no
        // longer describes.
        invalidateOnEdit(requestBodyArea, rootFieldField, leafFieldField,
                cycleFieldField, typeNameField, aliasPrefixField);

        generateBtn.addActionListener(e -> {
            invalidatePayload();
            withPayload("Generating", body -> { });
        });
        copyBtn.addActionListener(e -> withPayload("Generating", this::copy));
        repeaterBtn.addActionListener(e -> withPayload("Generating", this::toRepeater));
        updateVectorHelp();
    }

    private void invalidateOnEdit(JTextComponent... fields) {
        DocumentListener l = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                invalidatePayload();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                invalidatePayload();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                invalidatePayload();
            }
        };
        for (JTextComponent f : fields) {
            f.getDocument().addDocumentListener(l);
        }
    }

    /** Cancels an in-flight build. Called from the extension's unloading handler. */
    public void shutdown() {
        SwingWorker<String, Void> w = worker;
        if (w != null) {
            w.cancel(true);
        }
    }

    // ------------------------------------------------------------------ layout

    private JComponent buildForm() {
        JPanel outer = new JPanel(new BorderLayout(6, 6));
        outer.setBorder(BorderFactory.createTitledBorder("Target and payload"));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; top.add(new JLabel("Endpoint URL"), g);
        g.gridx = 1; g.gridwidth = 7; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        top.add(urlField, g);
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;

        g.gridx = 0; g.gridy = 1; top.add(new JLabel("Extra headers"), g);
        headersArea.setToolTipText("One per line, e.g. Authorization: Bearer xxx");
        g.gridx = 1; g.gridwidth = 7; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        top.add(new JScrollPane(headersArea), g);
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;

        g.gridx = 0; g.gridy = 2; top.add(new JLabel("Vector"), g);
        g.gridx = 1; top.add(vectorBox, g);
        g.gridx = 2; top.add(new JLabel("Count (N)"), g);
        countSpin.setToolTipText("Aliases, nesting levels, batched operations or directives, "
                + "depending on the vector.");
        g.gridx = 3; top.add(countSpin, g);
        g.gridx = 4; top.add(new JLabel("Alias prefix"), g);
        aliasPrefixField.setToolTipText("Aliases are prefix + index: 'a' gives a0, a1... "
                + "Change it if a WAF rule matches the default pattern.");
        g.gridx = 5; top.add(aliasPrefixField, g);

        g.gridx = 0; g.gridy = 3; g.gridwidth = 8;
        vectorHelp.setForeground(Ui.hint(api));
        top.add(vectorHelp, g);

        outer.add(top, BorderLayout.NORTH);
        modeTabs.addTab("Captured request", buildRawTab());
        modeTabs.addTab("Schema fields", buildSchemaTab());
        modeTabs.addChangeListener(e -> invalidatePayload());
        outer.add(modeTabs, BorderLayout.CENTER);
        return outer;
    }

    /**
     * Preferred input: the request body exactly as Burp shows it. The JSON
     * envelope is kept verbatim and only the "query" value is replaced, so
     * operationName, variables and extensions all survive.
     */
    private JComponent buildRawTab() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(new JLabel("Request body from Burp (JSON), or a bare GraphQL operation. "
                + "Everything except \"query\" is preserved."), BorderLayout.NORTH);
        requestBodyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        p.add(new JScrollPane(requestBodyArea), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildSchemaTab() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.NORTHWEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("Root field"), g);
        rootFieldField.setToolTipText("Field with arguments, e.g. user(id:1)");
        g.gridx = 1; p.add(rootFieldField, g);
        g.gridx = 2; p.add(new JLabel("Leaf field"), g);
        g.gridx = 3; p.add(leafFieldField, g);

        g.gridx = 0; g.gridy = 1; p.add(new JLabel("Cycle field"), g);
        cycleFieldField.setToolTipText("Self-referencing edge used for nesting, e.g. friends. "
                + "Also used by the recursion vectors on the Captured request tab, where it is "
                + "combined with the captured operation's own root field and variables.");
        g.gridx = 1; p.add(cycleFieldField, g);
        g.gridx = 2; p.add(new JLabel("Type name"), g);
        typeNameField.setToolTipText("The type the cycle field returns. Needed by the two "
                + "fragment-based vectors.");
        g.gridx = 3; p.add(typeNameField, g);
        g.gridx = 4; p.add(new JLabel("Fan-out"), g);
        breadthSpin.setToolTipText("Refs per level for 'Nested + alias'. Expansion is fan-out^N.");
        g.gridx = 5; p.add(breadthSpin, g);

        g.gridx = 0; g.gridy = 2; g.weighty = 1; g.fill = GridBagConstraints.BOTH;
        p.add(new JPanel(), g);
        return p;
    }

    private JComponent buildOutput() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createTitledBorder("Generated payload"));
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        output.setLineWrap(true);
        // Generated content, and possibly a truncated view of it. Edit in
        // Repeater, where what you see is what gets sent.
        output.setEditable(false);
        p.add(new JScrollPane(output), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildFooter() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(generateBtn);
        buttons.add(copyBtn);
        buttons.add(repeaterBtn);
        p.add(buttons, BorderLayout.WEST);
        status.setForeground(Ui.hint(api));
        p.add(status, BorderLayout.SOUTH);
        return p;
    }

    private void updateVectorHelp() {
        PayloadFactory.Vector v = (PayloadFactory.Vector) vectorBox.getSelectedItem();
        vectorHelp.setText(v == null ? " " : v.help);
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

            String body = req.bodyToString();
            if (!body.trim().isEmpty()) {
                requestBodyArea.setText(body);
                requestBodyArea.setCaretPosition(0);
                modeTabs.setSelectedIndex(0);
            }
            invalidatePayload();
            status.setText("Imported " + req.url());
        });
    }

    // ----------------------------------------------------------------- actions

    /** Snapshot of the form, taken on the EDT and handed to the build thread. */
    private PayloadFactory.Config snapshot() {
        PayloadFactory.Config c = new PayloadFactory.Config();
        c.rootField = rootFieldField.getText().trim();
        c.leafField = leafFieldField.getText().trim();
        c.cycleField = cycleFieldField.getText().trim();
        c.typeName = typeNameField.getText().trim();
        c.breadth = (Integer) breadthSpin.getValue();
        c.aliasPrefix = aliasPrefixField.getText();
        c.opName = cfg.opName;
        c.requestBody = modeTabs.getSelectedIndex() == 0 ? requestBodyArea.getText() : "";
        return c;
    }

    private void invalidatePayload() {
        payload = "";
        output.setText("");
    }

    /**
     * Gets the payload to the given action, building it first if needed.
     *
     * The build runs on a worker thread. Multiplying a captured field a few
     * hundred thousand times is seconds of string work and hundreds of
     * megabytes; on the Swing thread that is a frozen Burp, not a slow button.
     */
    private void withPayload(String label, Consumer<String> then) {
        String existing = payload;
        if (existing != null && !existing.isEmpty()) {
            then.accept(existing);
            return;
        }
        PayloadFactory.Vector v = (PayloadFactory.Vector) vectorBox.getSelectedItem();
        if (v == null) {
            return;
        }
        int n = (Integer) countSpin.getValue();
        PayloadFactory.Config snap = snapshot();

        setBusy(true);
        status.setText(String.format("%s %s at N=%,d...", label, v.label, n));

        SwingWorker<String, Void> w = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return PayloadFactory.body(v, snap, n);
            }

            @Override
            protected void done() {
                worker = null;
                setBusy(false);
                if (isCancelled()) {
                    status.setText("Build cancelled.");
                    return;
                }
                String body;
                try {
                    body = get();
                } catch (CancellationException ce) {
                    status.setText("Build cancelled.");
                    return;
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (ExecutionException ee) {
                    Throwable cause = ee.getCause() == null ? ee : ee.getCause();
                    payload = "";
                    output.setText("");
                    status.setText(String.valueOf(cause.getMessage()));
                    JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            cause.getMessage(), "Cannot build payload", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                payload = body;
                showPreview(body);
                status.setText(describe(v, snap, n, body));
                then.accept(body);
            }
        };
        worker = w;
        w.execute();
    }

    private void showPreview(String body) {
        if (body.length() <= PREVIEW_LIMIT) {
            output.setText(body);
        } else {
            output.setText(body.substring(0, PREVIEW_LIMIT)
                    + String.format("%n%n... preview truncated at %,d of %,d bytes. "
                            + "Copy or Send to Repeater uses the whole payload.%n",
                            PREVIEW_LIMIT, body.length()));
        }
        output.setCaretPosition(0);
    }

    private String describe(PayloadFactory.Vector v, PayloadFactory.Config c, int n, String body) {
        long nodes = PayloadFactory.estimatedNodes(v, c, n);
        return String.format("%s, N=%,d -> %,d bytes, ~%,d nodes server-side.%s",
                v.label, n, body.length(), nodes,
                body.length() > 5_000_000
                        ? "  Large body: a proxy or size limit may reject this before the server costs it."
                        : "");
    }

    private void setBusy(boolean busy) {
        generateBtn.setEnabled(!busy);
        copyBtn.setEnabled(!busy);
        repeaterBtn.setEnabled(!busy);
    }

    private void copy(String body) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(body), null);
        status.setText(String.format("Copied %,d bytes to clipboard.", body.length()));
    }

    private void toRepeater(String body) {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            status.setText("Set an endpoint URL first.");
            return;
        }
        PayloadFactory.Vector v = (PayloadFactory.Vector) vectorBox.getSelectedItem();
        int n = (Integer) countSpin.getValue();
        api.repeater().sendToRepeater(buildRequest(url, body),
                "gqldos " + (v == null ? "payload" : v.name().toLowerCase()) + " N=" + n);
        status.setText(String.format("Sent to Repeater: %s, N=%,d, %,d bytes.",
                v == null ? "payload" : v.label, n, body.length()));
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
}
