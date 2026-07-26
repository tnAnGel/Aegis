import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Shield, Loader2, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";

/**
 * V2 LoginPage
 *
 * Full-screen sign-in form styled to the V2 dark navy/green mockup theme.
 * Rendered directly by main.tsx when auth state is "logged_out" —
 * no router or layout wrapper involved.
 *
 * Behaviour is IDENTICAL to V1 LoginPage:
 *   - Calls useAuth().login(email, password)
 *   - Maps 401 → "Invalid email or password."
 *   - Maps other errors → "Login failed (status)."
 *   - Tracks busy/error state via local useState
 *
 * V2 additions:
 *   - Password visibility toggle (show/hide)
 *   - Brand lockup with green-tinted shield badge
 *   - v2-card chrome (rounded-xl, border, shadow via --v2-card-shadow)
 *   - Tabular-nums on any numeric elements
 */
export function LoginV2Page() {
    const { t } = useTranslation(["login", "common"]);
    const { login } = useAuth();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function handleSubmit(e: React.FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
            await login(email.trim(), password);
        } catch (err) {
            const e = err as { status?: number; body?: string };
            setError(
                e.status === 401
                    ? t("error.invalidCredentials")
                    : t("error.generic", { status: e.status ?? t("error.network") }),
            );
        } finally {
            setBusy(false);
        }
    }

    return (
        <div
            className="min-h-screen flex flex-col items-center justify-center p-6"
            style={{ background: "hsl(var(--background))" }}
        >
            {/* Brand lockup above card */}
            <div className="flex items-center gap-3 mb-8 select-none">
                <span
                    className="flex items-center justify-center w-10 h-10 rounded-xl"
                    style={{
                        background: "hsl(var(--primary) / 0.15)",
                        border: "1px solid hsl(var(--primary) / 0.30)",
                    }}
                    aria-hidden
                >
                    <Shield className="h-5 w-5" style={{ color: "hsl(var(--primary))" }} />
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

            {/* Login card */}
            <div
                className="v2-card w-full max-w-sm px-8 py-8"
                style={{ boxShadow: "var(--v2-card-shadow)" }}
            >
                {/* Card header */}
                <div className="mb-6 space-y-1">
                    <h1
                        className="text-lg font-semibold tracking-tight"
                        style={{ color: "hsl(var(--foreground))" }}
                    >
                        {t("title")}
                    </h1>
                    <p className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
                        {t("subtitle")}
                    </p>
                </div>

                <form className="space-y-4" onSubmit={handleSubmit} noValidate>
                    {/* Email field */}
                    <div className="space-y-1.5">
                        <Label
                            htmlFor="v2-email"
                            className="text-xs font-medium uppercase tracking-wider"
                            style={{ color: "hsl(var(--muted-foreground))" }}
                        >
                            {t("email")}
                        </Label>
                        <Input
                            id="v2-email"
                            type="email"
                            autoComplete="email"
                            autoFocus
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            placeholder={t("email.placeholder")}
                            className="bg-background border-input text-foreground placeholder:text-muted-foreground/50 focus-visible:ring-1 focus-visible:ring-primary"
                        />
                    </div>

                    {/* Password field with show/hide toggle */}
                    <div className="space-y-1.5">
                        <Label
                            htmlFor="v2-password"
                            className="text-xs font-medium uppercase tracking-wider"
                            style={{ color: "hsl(var(--muted-foreground))" }}
                        >
                            {t("password")}
                        </Label>
                        <div className="relative">
                            <Input
                                id="v2-password"
                                type={showPassword ? "text" : "password"}
                                autoComplete="current-password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                placeholder="••••••••"
                                className="bg-background border-input text-foreground placeholder:text-muted-foreground/50 focus-visible:ring-1 focus-visible:ring-primary pr-10"
                            />
                            <button
                                type="button"
                                className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground hover:text-foreground transition-colors"
                                onClick={() => setShowPassword((v) => !v)}
                                aria-label={showPassword ? t("password.hide") : t("password.show")}
                                tabIndex={-1}
                            >
                                {showPassword
                                    ? <EyeOff className="h-4 w-4" />
                                    : <Eye className="h-4 w-4" />
                                }
                            </button>
                        </div>
                    </div>

                    {/* Error message */}
                    {error && (
                        <p
                            role="alert"
                            className="text-sm rounded-lg px-3 py-2.5 border"
                            style={{
                                color: "hsl(var(--destructive))",
                                background: "hsl(var(--destructive) / 0.10)",
                                borderColor: "hsl(var(--destructive) / 0.35)",
                            }}
                        >
                            {error}
                        </p>
                    )}

                    {/* Submit */}
                    <Button
                        type="submit"
                        className="w-full mt-1"
                        disabled={busy}
                        style={
                            !busy
                                ? {
                                      background: "hsl(var(--primary))",
                                      color: "hsl(var(--primary-foreground))",
                                  }
                                : undefined
                        }
                    >
                        {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                        {busy ? t("signingIn") : t("signIn")}
                    </Button>
                </form>

                {/* Divider */}
                <div className="mt-6 border-t" style={{ borderColor: "hsl(var(--border))" }} />

                {/* Forgot password hint */}
                <p
                    className="mt-4 text-[11px] text-center leading-relaxed"
                    style={{ color: "hsl(var(--muted-foreground) / 0.7)" }}
                >
                    {t("forgot.prefix")}{" "}
                    <code
                        className="font-mono px-1 py-0.5 rounded text-[10px]"
                        style={{
                            background: "hsl(var(--muted))",
                            color: "hsl(var(--foreground))",
                        }}
                    >
                        aegis web reset-admin
                    </code>{" "}
                    {t("forgot.suffix")}
                </p>
            </div>

            {/* Footer tagline */}
            <p
                className="mt-8 text-[11px] tracking-wide"
                style={{ color: "hsl(var(--muted-foreground) / 0.4)" }}
            >
                {t("footer.tagline")}
            </p>
        </div>
    );
}
