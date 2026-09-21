package gqldos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;

import javax.swing.UIManager;
import java.awt.Color;

/**
 * Theme-aware colours.
 *
 * Burp ships a light and a dark look and feel, and the user can switch between
 * them while the extension is loaded. Hard-coded greys and reds are legible in
 * one and close to invisible in the other, so every colour here is resolved
 * against the current theme at paint time rather than stored as a constant.
 */
final class Ui {

    private Ui() {
    }

    private static boolean dark(MontoyaApi api) {
        try {
            return api.userInterface().currentTheme() == Theme.DARK;
        } catch (RuntimeException e) {
            // Fall back to a luminance test on the panel background.
            Color bg = UIManager.getColor("Panel.background");
            return bg != null && luminance(bg) < 0.5;
        }
    }

    private static double luminance(Color c) {
        return (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255.0;
    }

    /** Muted text: help lines, status bars, captions. */
    static Color hint(MontoyaApi api) {
        Color c = UIManager.getColor("Label.disabledForeground");
        if (c == null) {
            c = UIManager.getColor("textInactiveText");
        }
        return c != null ? c : (dark(api) ? new Color(0xA0, 0xA0, 0xA0) : new Color(0x50, 0x50, 0x50));
    }

    /** Default body text, used when no verdict colour applies. */
    static Color normal(MontoyaApi api) {
        Color c = UIManager.getColor("Label.foreground");
        return c != null ? c : (dark(api) ? Color.WHITE : Color.BLACK);
    }

    /** A missing control. Tuned for contrast on each theme's table background. */
    static Color bad(MontoyaApi api) {
        return dark(api) ? new Color(0xFF, 0x7B, 0x72) : new Color(0xC0, 0x39, 0x2B);
    }

    /** A control that fired. */
    static Color good(MontoyaApi api) {
        return dark(api) ? new Color(0x5C, 0xC8, 0x8A) : new Color(0x27, 0x80, 0x4F);
    }
}
