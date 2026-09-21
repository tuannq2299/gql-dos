package gqldos;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class GqlDosExtension implements BurpExtension {

    private static final String NAME = "GraphQL DoS Probe";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        DosPanel generator = new DosPanel(api);
        ScanPanel scanner = new ScanPanel(api);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Generator", generator);
        tabs.addTab("Scanner", scanner);
        api.userInterface().applyThemeToComponent(tabs);
        api.userInterface().registerSuiteTab("GraphQL DoS", tabs);

        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                // Only offer the item where there is actually a request to import.
                if (resolve(event).isEmpty()) {
                    return Collections.emptyList();
                }
                JMenuItem item = new JMenuItem("Send to GraphQL DoS Probe");
                item.addActionListener(e -> resolve(event).ifPresent(rr -> {
                    generator.loadFrom(rr.request());
                    scanner.loadFrom(rr.request());
                }));
                return Collections.singletonList(item);
            }
        });

        // Required by the BApp Store criteria: background threads must stop
        // when the extension is unloaded, otherwise an in-flight scan keeps
        // sending requests at the target after the user has unloaded us.
        api.extension().registerUnloadingHandler(() -> {
            scanner.shutdown();
            generator.shutdown();
            api.logging().logToOutput(NAME + " unloaded; background work stopped.");
        });

        api.logging().logToOutput(NAME + " loaded. Tab: 'GraphQL DoS' (Scanner, Generator).");
    }

    private static Optional<HttpRequestResponse> resolve(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return Optional.of(event.messageEditorRequestResponse().get().requestResponse());
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        return selected.isEmpty() ? Optional.empty() : Optional.of(selected.get(0));
    }
}
