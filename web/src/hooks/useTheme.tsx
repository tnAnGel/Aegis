import * as React from "react";

type Theme = "dark" | "light";

const STORAGE_KEY = "aegis_theme";

function applyTheme(t: Theme) {
    const el = document.documentElement;
    el.classList.remove("dark", "light");
    el.classList.add(t);
}

const ThemeContext = React.createContext<{
    theme: Theme;
    toggle: () => void;
} | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [theme, setTheme] = React.useState<Theme>(() => {
        const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
        return stored ?? "dark";
    });
    React.useEffect(() => {
        applyTheme(theme);
        localStorage.setItem(STORAGE_KEY, theme);
    }, [theme]);
    const toggle = React.useCallback(() => {
        setTheme((cur) => (cur === "dark" ? "light" : "dark"));
    }, []);
    return (
        <ThemeContext.Provider value={{ theme, toggle }}>{children}</ThemeContext.Provider>
    );
}

export function useTheme() {
    const ctx = React.useContext(ThemeContext);
    if (!ctx) throw new Error("useTheme must be used within <ThemeProvider>");
    return ctx;
}
