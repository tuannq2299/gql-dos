package gqldos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Payload generator. Builds a GraphQL resource-consumption payload at a
 * chosen size and hands it to Repeater or the clipboard. It never sends a
 * request itself -- firing stays a deliberate act in Repeater.
 */
public class DosPanel extends JPanel {

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

    public DosPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildForm(), buildOutput());
        split.setResizeWeight(0.55);
        add(split, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        vectorBox.addActionListener(e -> updateVectorHelp());
        generateBtn.addActionListener(e -> generate());
        copyBtn.addActionListener(e -> copy());
        repeaterBtn.addActionListener(e -> toRepeater());
        updateVectorHelp();
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
        vectorHelp.setForeground(new Color(0x60, 0x60, 0x60));
        top.add(vectorHelp, g);

        outer.add(top, BorderLayout.NORTH);
        modeTabs.addTab("Captured request", buildRawTab());
        modeTabs.addTab("Schema fields", buildSchemaTab());
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
                + "Schemas without one cannot be tested for depth or amplification.");
        g.gridx = 1; p.add(cycleFieldField, g);
        g.gridx = 2; p.add(new JLabel("Type name"), g);
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
            status.setText("Imported " + req.url());
        });
    }

    // ----------------------------------------------------------------- actions

    private void readConfig() {
        cfg.rootField = rootFieldField.getText().trim();
        cfg.leafField = leafFieldField.getText().trim();
        cfg.cycleField = cycleFieldField.getText().trim();
        cfg.typeName = typeNameField.getText().trim();
        cfg.breadth = (Integer) breadthSpin.getValue();
        cfg.aliasPrefix = aliasPrefixField.getText();
        cfg.requestBody = modeTabs.getSelectedIndex() == 0 ? requestBodyArea.getText() : "";
    }

    private String build() {
        readConfig();
        PayloadFactory.Vector v = (PayloadFactory.Vector) vectorBox.getSelectedItem();
        int n = (Integer) countSpin.getValue();
        String body = PayloadFactory.body(v, cfg, n);
        long nodes = PayloadFactory.estimatedNodes(v, cfg, n);
        status.setText(String.format("%s, N=%,d -> %,d bytes, ~%,d nodes server-side.%s",
                v.label, n, body.length(), nodes,
                body.length() > 5_000_000 ? "  Large body: a proxy or size limit may reject this before the server costs it." : ""));
        return body;
    }

    private void generate() {
        try {
            String body = build();
            output.setText(body);
            output.setCaretPosition(0);
        } catch (Exception ex) {
            output.setText("");
            status.setText(ex.getMessage());
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Cannot build payload", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void copy() {
        String body = output.getText();
        if (body.isEmpty()) {
            try {
                body = build();
                output.setText(body);
            } catch (Exception ex) {
                status.setText(ex.getMessage());
                return;
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(body), null);
        status.setText(String.format("Copied %,d bytes to clipboard.", body.length()));
    }

    private void toRepeater() {
        try {
            String body = output.getText().isEmpty() ? build() : output.getText();
            output.setText(body);
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                status.setText("Set an endpoint URL first.");
                return;
            }
            PayloadFactory.Vector v = (PayloadFactory.Vector) vectorBox.getSelectedItem();
            int n = (Integer) countSpin.getValue();
            api.repeater().sendToRepeater(buildRequest(url, body),
                    "gqldos " + v.name().toLowerCase() + " N=" + n);
            status.setText(String.format("Sent to Repeater: %s, N=%,d, %,d bytes.",
                    v.label, n, body.length()));
        } catch (Exception ex) {
            status.setText("Cannot build payload: " + ex.getMessage());
        }
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
