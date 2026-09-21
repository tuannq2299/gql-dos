package gqldos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;

import javax.swing.JLabel;
import javax.swing.UIManager;
import java.awt.Color;
import java.util.function.Supplier;

/**
 * Theme-aware colours.
 *
 * Burp ships a light and a dark look and feel, and the user can switch between
 * them while the extension is loaded. Hard-coded greys and reds are legible in
 * one and close to invisible in the other, so every colour here is looked up on
 * each call. {@link #hintLabel} resolves inside {@code getForeground()}, which
 * Swing calls on every paint, so a theme switch is picked up without a reload.
 */
final class Ui {

    private Ui() {
    }

    private static boolean dark(MontoyaApi api) {
        if (api != null) {
            try {
                return api.userInterface().currentTheme() == Theme.DARK;
            } catch (RuntimeException ignored) {
                // Fall through to the luminance test below.
            }
        }
        Color bg = UIManager.getColor("Panel.background");
        return bg != null && luminance(bg) < 0.5;
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

    /** A missing control. Tuned for contrast on each theme's table background. */
    static Color bad(MontoyaApi api) {
        return dark(api) ? new Color(0xFF, 0x7B, 0x72) : new Color(0xC0, 0x39, 0x2B);
    }

    /** A control that fired. */
    static Color good(MontoyaApi api) {
        return dark(api) ? new Color(0x5C, 0xC8, 0x8A) : new Color(0x27, 0x80, 0x4F);
    }

    /**
     * A label painted in the muted colour, re-resolved on every paint.
     *
     * The api arrives through a supplier because these labels are built as
     * field initialisers, before the panel's constructor has stored it.
     */
    static JLabel hintLabel(Supplier<MontoyaApi> api, String text) {
        return new JLabel(text) {
            @Override
            public Color getForeground() {
                return Ui.hint(api.get());
            }
        };
    }
}
