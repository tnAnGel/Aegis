import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "@tanstack/react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { router } from "@/router";
import { queryClient } from "@/lib/queryClient";
import { Toaster } from "@/hooks/useToast";
import { ThemeProvider } from "@/hooks/useTheme";
import { AuthProvider, useAuth } from "@/hooks/useAuth";
import { LoginV2Page } from "@/pages/v2/Login";
import { ServiceUnavailableV2Page } from "@/pages/v2/ServiceUnavailable";
// Side-effect import: runs i18next.init() before the app renders. Must come
// before any component that calls useTranslation().
import "@/i18n";
import { useTranslation } from "react-i18next";
import "@/index.css";

// V2 is the one and only UI now. Pin the V2 theme tokens on the document root
// so even the pre-router auth screens (login / service-unavailable) render in
// the V2 palette.
document.documentElement.setAttribute("data-theme", "v2");

function AuthGate() {
    const { state } = useAuth();
    const { t } = useTranslation("common");
    if (state.status === "loading") {
        return (
            <div className="min-h-screen grid place-items-center text-sm text-muted-foreground bg-background">
                {t("loading")}
            </div>
        );
    }
    if (state.status === "service_unavailable") return <ServiceUnavailableV2Page />;
    if (state.status === "logged_out") return <LoginV2Page />;
    return <RouterProvider router={router} />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
        <ThemeProvider>
            <QueryClientProvider client={queryClient}>
                <Toaster>
                    <AuthProvider>
                        <AuthGate />
                    </AuthProvider>
                </Toaster>
            </QueryClientProvider>
        </ThemeProvider>
    </React.StrictMode>,
);
