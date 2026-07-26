import { Shield, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

/**
 * V2 ServiceUnavailablePage
 *
 * Full-screen 503 error page styled to the V2 mockup theme.
 * Rendered directly by main.tsx when auth state is "service_unavailable"
 * (an operator ran `aegis web stop`). No router or layout wrapper.
 *
 * Behaviour is identical to V1 — calls useAuth().refresh() on retry.
 * Only the presentation changes (V2 dark navy palette, amber accent for
 * 503 rather than green, v2-card chrome).
 */
export function ServiceUnavailableV2Page() {
    const { refresh } = useAuth();
    const { t } = useTranslation(["serviceunavailable", "common"]);

    return (
        <div
            className="min-h-screen flex flex-col items-center justify-center p-8 text-center"
            style={{ background: "hsl(var(--background))" }}
        >
            {/* Brand lockup */}
            <div className="flex items-center gap-3 mb-12 select-none">
                <span
                    className="flex items-center justify-center w-9 h-9 rounded-lg"
                    style={{
                        background: "hsl(var(--warning) / 0.12)",
                        border: "1px solid hsl(var(--warning) / 0.30)",
                    }}
                    aria-hidden
                >
                    <Shield className="h-5 w-5" style={{ color: "hsl(var(--warning))" }} />
                </span>
                <div className="text-left leading-none">
                    <p
                        className="text-base font-bold tracking-widest uppercase"
                        style={{ color: "hsl(var(--foreground))" }}
                    >
                        Aegis
                    </p>
                    <p
                        className="text-[0.6rem] tracking-[0.2em] uppercase mt-0.5"
                        style={{ color: "hsl(var(--muted-foreground))" }}
                    >
                        {t("brand.tagline")}
                    </p>
                </div>
            </div>

            {/* Giant status numeral */}
            <p
                className="text-[11rem] font-extrabold leading-none select-none tabular-nums"
                style={{ color: "hsl(var(--warning) / 0.08)" }}
                aria-hidden
            >
                503
            </p>

            {/* Card panel */}
            <div
                className="v2-card -mt-6 px-8 py-7 max-w-sm w-full text-center space-y-3"
                style={{ boxShadow: "var(--v2-card-shadow)" }}
            >
                <h1
                    className="text-xl font-semibold tracking-tight"
                    style={{ color: "hsl(var(--foreground))" }}
                >
                    {t("title")}
                </h1>
                <p className="text-sm leading-relaxed" style={{ color: "hsl(var(--muted-foreground))" }}>
                    {t("body.before")}
                    <code
                        className="font-mono text-xs px-1.5 py-0.5 rounded"
                        style={{
                            background: "hsl(var(--muted))",
                            border: "1px solid hsl(var(--border))",
                            color: "hsl(var(--foreground))",
                        }}
                    >
                        aegis web stop
                    </code>
                    {t("body.after")}
                </p>

                {/* Re-enable instructions */}
                <div className="text-left pt-1 space-y-2">
                    <p className="text-xs text-center" style={{ color: "hsl(var(--muted-foreground))" }}>
                        {t("reEnable")}
                    </p>
                    <pre
                        className="font-mono text-xs rounded-lg px-4 py-3 text-center"
                        style={{
                            background: "hsl(var(--muted) / 0.6)",
                            border: "1px solid hsl(var(--border))",
                            color: "hsl(var(--foreground))",
                        }}
                    >
                        aegis web start
                    </pre>
                </div>

                <div className="pt-2">
                    <Button
                        variant="secondary"
                        className="w-full"
                        onClick={() => void refresh()}
                    >
                        <RefreshCw className="h-4 w-4" />
                        {t("retry", { ns: "common" })}
                    </Button>
                </div>
            </div>

            {/* Footer */}
            <p
                className="mt-10 text-[11px] tracking-wide"
                style={{ color: "hsl(var(--muted-foreground) / 0.5)" }}
            >
                {t("footer")}
            </p>
        </div>
    );
}
