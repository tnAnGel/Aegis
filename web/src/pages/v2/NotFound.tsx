import { Link } from "@tanstack/react-router";
import { ArrowLeft, Shield } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

/**
 * V2 NotFoundPage
 *
 * Full-screen 404 error page styled to the V2 mockup theme.
 * Rendered by the router catch-all inside the /v2/* subtree —
 * AppLayoutV2 is NOT wrapped here (this page owns the full viewport).
 *
 * Behaviour is identical to V1 NotFoundPage; only the presentation
 * changes (V2 palette: navy-black bg, green accent, card chrome).
 */
export function NotFoundV2Page() {
    const { t } = useTranslation(["notfound", "common"]);
    return (
        <div className="min-h-screen flex flex-col items-center justify-center p-8 text-center"
             style={{ background: "hsl(var(--background))" }}
        >
            {/* Brand lockup */}
            <div className="flex items-center gap-3 mb-12 select-none">
                <span
                    className="flex items-center justify-center w-9 h-9 rounded-lg"
                    style={{ background: "hsl(var(--primary) / 0.15)", border: "1px solid hsl(var(--primary) / 0.30)" }}
                    aria-hidden
                >
                    <Shield className="h-5 w-5" style={{ color: "hsl(var(--primary))" }} />
                </span>
                <div className="text-left leading-none">
                    <p className="text-base font-bold tracking-widest uppercase" style={{ color: "hsl(var(--foreground))" }}>
                        Aegis
                    </p>
                    <p className="text-[0.6rem] tracking-[0.2em] uppercase mt-0.5" style={{ color: "hsl(var(--muted-foreground))" }}>
                        {t("brand.tagline")}
                    </p>
                </div>
            </div>

            {/* Giant status numeral */}
            <p
                className="text-[11rem] font-extrabold leading-none select-none tabular-nums"
                style={{ color: "hsl(var(--primary) / 0.08)" }}
                aria-hidden
            >
                404
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
                    {t("description")}
                </p>

                <div className="pt-3">
                    <Button asChild variant="default" className="w-full">
                        <Link to="/">
                            <ArrowLeft className="h-4 w-4" />
                            {t("backToDashboard")}
                        </Link>
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
