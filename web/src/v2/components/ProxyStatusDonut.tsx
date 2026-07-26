/**
 * ProxyStatusDonut — V2 Dashboard component
 *
 * A thin wrapper around the existing DonutChart that displays a three-slice
 * proxy-status breakdown: Active / Inactive / Error.
 *
 * Visual contract (V2 tokens):
 *   Active   → primary green  (#22d362)
 *   Inactive → muted blue     (#3b82f6) — same as challenge colour
 *   Error    → destructive red (#ef4444)
 *
 * The center label shows the total upstream count and a summary phrase
 * ("N upstreams").  When all upstreams are active it shows "All OK".
 *
 * Exported names:
 *   ProxyStatusDonutProps  — public prop type
 *   ProxyStatusDonut       — the component
 *
 * Usage:
 *   <ProxyStatusDonut active={12} inactive={2} error={1} height={200} />
 *
 * Deriving counts from existing API data:
 *   - `active`   — upstreams responding within healthy threshold
 *   - `inactive` — upstreams not listed in /admin/health unhealthy list
 *                  (i.e. sites count minus unhealthy count minus error count)
 *   - `error`    — upstreams in /admin/health unhealthy list
 *
 * If all three counts are zero the DonutChart will render its own "no data yet"
 * placeholder.
 */

import { DonutChart } from "@/components/charts/DonutChart";
import { compact } from "@/lib/format";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ProxyStatusDonutProps {
    /** Number of upstreams currently active / healthy. */
    active: number;
    /** Number of upstreams that are configured but not actively serving. */
    inactive?: number;
    /** Number of upstreams currently in error state. */
    error?: number;
    /** Height passed to DonutChart. Defaults to 200. */
    height?: number;
}

// ─── Colours (match V2 chart series tokens from tokens.css) ──────────────────

const COLOR_ACTIVE   = "#22d362"; // --v2-chart-allow
const COLOR_INACTIVE = "#3b82f6"; // --v2-chart-challenge (reused for inactive)
const COLOR_ERROR    = "#ef4444"; // --v2-chart-deny

// ─── Component ────────────────────────────────────────────────────────────────

export function ProxyStatusDonut({
    active,
    inactive = 0,
    error = 0,
    height = 200,
}: ProxyStatusDonutProps) {
    const total = active + inactive + error;

    // Build the slice array; omit zero-count slices to avoid thin slivers
    const slices = [
        { name: "Active",   value: active,   color: COLOR_ACTIVE },
        { name: "Inactive", value: inactive, color: COLOR_INACTIVE },
        { name: "Error",    value: error,    color: COLOR_ERROR },
    ].filter((s) => s.value > 0);

    // Center label
    const centerValue = compact(total);
    const centerLabel =
        total === 0
            ? "no data"
            : error === 0 && inactive === 0
            ? "all ok"
            : "upstreams";

    return (
        <DonutChart
            slices={slices}
            centerValue={centerValue}
            centerLabel={centerLabel}
            height={height}
        />
    );
}
