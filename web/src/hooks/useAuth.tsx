import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { authApi, clearToken, getToken, setToken } from "@/api/client";

type AuthState =
    | { status: "loading" }
    | { status: "logged_out" }
    | { status: "service_unavailable" }
    | { status: "logged_in"; email: string; mustChange: boolean; auth: "session" | "config_token" };

interface AuthContextValue {
    state: AuthState;
    login: (email: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    refresh: () => Promise<void>;
    markCredentialsChanged: (token: string, email: string) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Refresh strategy: we hit /me once on mount, then re-check whenever
// the token changes (login / logout / change-credentials). We do *not*
// poll — the server doesn't have a way to push session invalidation
// today; a stale token gets a 401 from the next real request and the
// client wrapper bumps us back to login.
export function AuthProvider({ children }: { children: ReactNode }) {
    const [state, setState] = useState<AuthState>({ status: "loading" });

    const refresh = useCallback(async () => {
        // Adopt a one-shot URL token (`#token=...`) BEFORE checking
        // localStorage. The login page renders before any TopBar (which
        // hosts TokenInput) gets mounted, so without this the hash
        // form of auth would only work for users who already had a
        // token saved.
        if (
            typeof location !== "undefined"
            && location.hash
            && location.hash.includes("token=")
        ) {
            const params = new URLSearchParams(location.hash.replace(/^#/, ""));
            const t = params.get("token");
            if (t) {
                setToken(t);
                history.replaceState(null, "", location.pathname + location.search);
            }
        }
        const token = getToken();
        if (!token) {
            setState({ status: "logged_out" });
            return;
        }
        try {
            const me = await authApi.me();
            setState({
                status: "logged_in",
                email: me.email ?? "",
                // Accept either field name (backend emits both; older builds only
                // `must_change_credentials`) so the forced-change flow fires.
                mustChange: me.must_change ?? me.must_change_credentials ?? false,
                auth: me.auth,
            });
        } catch (e) {
            const status = (e as { status?: number }).status;
            if (status === 503) {
                setState({ status: "service_unavailable" });
            } else {
                clearToken();
                setState({ status: "logged_out" });
            }
        }
    }, []);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    const login = useCallback(async (email: string, password: string) => {
        const r = await authApi.login(email, password);
        setToken(r.token);
        setState({
            status: "logged_in",
            // Fall back to the just-entered email if the response omits it.
            email: r.email ?? email,
            mustChange: r.must_change ?? r.must_change_credentials ?? false,
            auth: "session",
        });
    }, []);

    const logout = useCallback(async () => {
        try {
            await authApi.logout();
        } catch {
            // best-effort — even if the server is down we clear locally
        }
        clearToken();
        setState({ status: "logged_out" });
    }, []);

    const markCredentialsChanged = useCallback((token: string, email: string) => {
        setToken(token);
        setState({ status: "logged_in", email, mustChange: false, auth: "session" });
    }, []);

    const value = useMemo<AuthContextValue>(
        () => ({ state, login, logout, refresh, markCredentialsChanged }),
        [state, login, logout, refresh, markCredentialsChanged],
    );

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
    return ctx;
}
