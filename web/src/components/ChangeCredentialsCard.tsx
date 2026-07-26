import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { authApi } from "@/api/client";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/useToast";

export function ChangeCredentialsCard() {
    const { state, markCredentialsChanged } = useAuth();
    const { toast } = useToast();
    const mustChange = state.status === "logged_in" && state.mustChange;
    const currentEmail = state.status === "logged_in" ? state.email : "";

    const [currentPassword, setCurrentPassword] = useState("");
    const [newEmail, setNewEmail] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function handleSubmit(e: React.FormEvent) {
        e.preventDefault();
        if (busy) return;
        setError(null);
        if (newPassword.length < 8) {
            setError("New password must be at least 8 characters.");
            return;
        }
        if (newPassword !== confirmPassword) {
            setError("New passwords do not match.");
            return;
        }
        setBusy(true);
        try {
            const r = await authApi.changeCredentials(currentPassword, newEmail.trim(), newPassword);
            markCredentialsChanged(r.token, r.email);
            toast({ title: "Credentials updated", variant: "success" });
            setCurrentPassword("");
            setNewPassword("");
            setConfirmPassword("");
        } catch (err) {
            const e = err as { status?: number; body?: string };
            try {
                const parsed = JSON.parse(e.body ?? "{}");
                setError(parsed.error ?? `HTTP ${e.status}`);
            } catch {
                setError(`HTTP ${e.status}`);
            }
        } finally {
            setBusy(false);
        }
    }

    return (
        <Card className={mustChange ? "border-destructive/60" : undefined}>
            <CardHeader>
                <CardTitle className="text-sm">
                    {mustChange ? "Set a real admin password" : "Change credentials"}
                </CardTitle>
                <CardDescription>
                    {mustChange
                        ? "You're using the installer defaults. Pick a new email + password before anything else."
                        : "Update the email + password used to sign in to this panel."}
                </CardDescription>
            </CardHeader>
            <CardContent>
                <form className="space-y-3" onSubmit={handleSubmit}>
                    <div className="space-y-1.5">
                        <Label htmlFor="cur-pwd">Current password</Label>
                        <Input
                            id="cur-pwd"
                            type="password"
                            autoComplete="current-password"
                            value={currentPassword}
                            onChange={(e) => setCurrentPassword(e.target.value)}
                            required
                        />
                    </div>
                    <div className="space-y-1.5">
                        <Label htmlFor="new-email">New email</Label>
                        <Input
                            id="new-email"
                            type="email"
                            autoComplete="username"
                            placeholder={currentEmail || undefined}
                            value={newEmail}
                            onChange={(e) => setNewEmail(e.target.value)}
                            required
                        />
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2">
                        <div className="space-y-1.5">
                            <Label htmlFor="new-pwd">New password</Label>
                            <Input
                                id="new-pwd"
                                type="password"
                                autoComplete="new-password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                required
                                minLength={8}
                            />
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="confirm-pwd">Confirm</Label>
                            <Input
                                id="confirm-pwd"
                                type="password"
                                autoComplete="new-password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                                minLength={8}
                            />
                        </div>
                    </div>
                    {error && (
                        <p role="alert" className="text-sm text-destructive border border-destructive/40 bg-destructive/10 rounded-md px-3 py-2">
                            {error}
                        </p>
                    )}
                    <Button type="submit" disabled={busy} size="sm">
                        {busy ? "Saving…" : "Save credentials"}
                    </Button>
                </form>
            </CardContent>
        </Card>
    );
}
