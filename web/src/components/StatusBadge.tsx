import { Badge } from "@/components/ui/badge";

interface Props {
    state: "ok" | "warn" | "error" | "muted";
    children: React.ReactNode;
}

export function StatusBadge({ state, children }: Props) {
    const variant =
        state === "ok"
            ? "success"
            : state === "warn"
              ? "warning"
              : state === "error"
                ? "destructive"
                : "muted";
    return <Badge variant={variant}>{children}</Badge>;
}
