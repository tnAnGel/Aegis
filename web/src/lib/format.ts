// Tiny formatters used across pages. Kept dependency-free.

export function compact(n: number | null | undefined): string {
    if (n == null || isNaN(n)) return "—";
    if (n < 1_000) return n.toString();
    if (n < 1_000_000) return `${(n / 1_000).toFixed(1)}k`;
    if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    return `${(n / 1_000_000_000).toFixed(2)}B`;
}

export function pct(num: number, denom: number): string {
    if (!denom) return "0%";
    return `${((num / denom) * 100).toFixed(1)}%`;
}

export function ago(ts: number | null | undefined): string {
    if (!ts) return "—";
    const now = Date.now() / 1000;
    const diff = Math.max(0, Math.floor(now - ts));
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

export function bytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}
