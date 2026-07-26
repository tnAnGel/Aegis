import { useEffect, useRef, useState } from "react";

/// V171 — rolling time-series buffer for cumulative metrics.
///
/// Aegis exposes Prometheus-style cumulative counters
/// (aegis_requests_total grows monotonically). The dashboard polls
/// every N seconds. To render a live req/s area chart we need:
///   1. A bounded ring buffer of the last K polls
///   2. Each point = delta-from-previous / elapsed-seconds
///
/// This hook owns that buffer. Pass it the latest cumulative value
/// and the timestamp; get back a series suitable for Recharts.
///
/// `keepPoints` defaults to 60 — matches a 5-minute window at the
/// 5s polling cadence the dashboard uses.

export interface SeriesPoint {
    /** Unix epoch ms — useful for x-axis labelling. */
    t: number;
    /** Per-second rate (delta / interval). 0 for the first sample. */
    v: number;
}

export function useTimeSeries(
    cumulative: number | undefined,
    keepPoints: number = 60,
): SeriesPoint[] {
    const [series, setSeries] = useState<SeriesPoint[]>([]);
    const lastRef = useRef<{ t: number; v: number } | null>(null);

    useEffect(() => {
        if (cumulative === undefined || !Number.isFinite(cumulative)) return;
        const now = Date.now();
        const last = lastRef.current;
        if (last === null) {
            // First sample — anchor the baseline, don't emit a delta
            // (would be misleadingly huge).
            lastRef.current = { t: now, v: cumulative };
            return;
        }
        const elapsed = (now - last.t) / 1000;
        if (elapsed <= 0) return;
        // Counter resets (process restart) make cumulative go BACKWARDS.
        // Show 0 instead of a negative bar.
        const delta = Math.max(0, cumulative - last.v);
        const rate = delta / elapsed;
        lastRef.current = { t: now, v: cumulative };
        setSeries((prev) => {
            const next = [...prev, { t: now, v: rate }];
            return next.length > keepPoints
                ? next.slice(next.length - keepPoints)
                : next;
        });
    }, [cumulative, keepPoints]);

    return series;
}

/// V171 — like useTimeSeries but for MULTIPLE cumulative inputs that
/// share a timeline. Aligned by the same poll boundaries so a stacked
/// area chart looks coherent. Returns one row per poll with all the
/// series values keyed by name.
export function useTimeSeriesMulti(
    cumulatives: Record<string, number | undefined>,
    keepPoints: number = 60,
): Array<{ t: number } & Record<string, number>> {
    const [rows, setRows] = useState<Array<{ t: number } & Record<string, number>>>([]);
    const lastRef = useRef<{ t: number; v: Record<string, number> } | null>(null);

    // Hash the keys+values for the effect deps. Stable per poll.
    const hash = Object.entries(cumulatives)
        .map(([k, v]) => `${k}=${v ?? "u"}`)
        .join("|");

    useEffect(() => {
        // Skip if any value is undefined (incomplete data).
        const values: Record<string, number> = {};
        for (const [k, v] of Object.entries(cumulatives)) {
            if (v === undefined || !Number.isFinite(v)) return;
            values[k] = v;
        }
        const now = Date.now();
        const last = lastRef.current;
        if (last === null) {
            lastRef.current = { t: now, v: values };
            return;
        }
        const elapsed = (now - last.t) / 1000;
        if (elapsed <= 0) return;
        const row: { t: number } & Record<string, number> = { t: now };
        for (const k of Object.keys(values)) {
            const curr = values[k] ?? 0;
            const prev = last.v[k] ?? 0;
            const delta = Math.max(0, curr - prev);
            row[k] = delta / elapsed;
        }
        lastRef.current = { t: now, v: values };
        setRows((prev) => {
            const next = [...prev, row];
            return next.length > keepPoints
                ? next.slice(next.length - keepPoints)
                : next;
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [hash, keepPoints]);

    return rows;
}
