import * as React from "react";
import {
    Toast,
    ToastClose,
    ToastDescription,
    ToastProvider,
    ToastTitle,
    ToastViewport,
} from "@/components/ui/toast";

interface ToastEntry {
    id: number;
    title?: string;
    description?: string;
    variant?: "default" | "destructive" | "success";
}

const ToastContext = React.createContext<{
    toast: (t: Omit<ToastEntry, "id">) => void;
} | null>(null);

let seq = 0;

export function Toaster({ children }: { children: React.ReactNode }) {
    const [toasts, setToasts] = React.useState<ToastEntry[]>([]);
    const push = React.useCallback((t: Omit<ToastEntry, "id">) => {
        const id = ++seq;
        setToasts((cur) => [...cur, { ...t, id }]);
        // Auto-remove after a few seconds; Radix handles its own
        // exit animation when we drop the entry.
        setTimeout(() => {
            setToasts((cur) => cur.filter((x) => x.id !== id));
        }, 5000);
    }, []);
    return (
        <ToastContext.Provider value={{ toast: push }}>
            <ToastProvider swipeDirection="right">
                {children}
                {toasts.map((t) => (
                    <Toast key={t.id} variant={t.variant}>
                        <div className="grid gap-1">
                            {t.title && <ToastTitle>{t.title}</ToastTitle>}
                            {t.description && (
                                <ToastDescription>{t.description}</ToastDescription>
                            )}
                        </div>
                        <ToastClose />
                    </Toast>
                ))}
                <ToastViewport />
            </ToastProvider>
        </ToastContext.Provider>
    );
}

export function useToast() {
    const ctx = React.useContext(ToastContext);
    if (!ctx) throw new Error("useToast must be used within <Toaster>");
    return ctx;
}
