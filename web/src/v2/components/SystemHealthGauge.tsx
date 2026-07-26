/**
 * SystemHealthGauge — V2 Dashboard component
 *
 * A thin wrapper around the existing ArcGauge component that:
 *   1. Accepts a 0-100 percentage value (or raw value + max) for a single
 *      system metric (CPU / Memory / Disk / Network).
 *   2. Derives the arc colour automatically from threshold rules so the
 *      caller does not have to think about it.
 *   3. Exposes a convenience `pct` prop for the common "percentage of max"
 *      use-case, or raw `value` + `max` for when units matter (e.g. MB).
 *
 * Colour thresholds (applied to the 0-100 normalised percentage):
 *   < 70%  → cyan   (healthy)
 *   < 90%  → amber  (warning)
 *   >= 90% → violet (critical — note: ArcGauge only has cyan/violet/amber)
 *
 * Exported names:
 *   SystemHealthGaugeProps  — public prop type
 *   SystemHealthGauge       — the component
 *
 * Usage examples:
 *   // CPU — percentage directly
 *   <SystemHealthGauge label="CPU" pct={42.5} unit="%" />
 *
 *   // Memory — raw value + max
 *   <SystemHealthGauge label="Memory" value={7800} max={16384} unit="MB" />
 *
 *   // Network — byte throughput as percentage of a capacity cap
 *   <SystemHealthGauge label="Network" value={rxBytes} max={maxBytesPerSec} unit="Mb/s" />
 */

import { ArcGauge } from "@/components/charts/ArcGauge";

// ─── Types ────────────────────────────────────────────────────────────────────

type ArcColor = "cyan" | "violet" | "amber";

export interface SystemHealthGaugeProps {
    /**
     * Short label displayed below the arc, e.g. "CPU", "Memory", "Disk",
     * "Network".
     */
    label: string;

    /**
     * Pre-computed percentage (0–100).  Use this for metrics where you already
     * have a ratio (CPU%), OR derive it from `value / max * 100`.
     * If both `pct` and `value`/`max` are provided, `pct` takes precedence.
     */
    pct?: number;

    /**
     * Raw current value (same unit as `max` and `unit`).
     * Used when you want the gauge to show real units (e.g. MB used).
     */
    value?: number;

    /**
     * Maximum for the raw value.  Ignored when `pct` is supplied.
     * Defaults to 100 (so you can just pass `value` as a percentage).
     */
    max?: number;

    /**
     * Unit label displayed inside the gauge beneath the numeric readout,
     * e.g. "%", "MB", "Mb/s".
     */
    unit?: string;

    /**
     * Override the automatic threshold-based colour selection.
     * Pass this only when the metric semantics differ from the standard
     * low=good / high=bad assumption (e.g. cache-hit-rate where high is good).
     */
    color?: ArcColor;
}

// ─── Colour thresholds ────────────────────────────────────────────────────────

function deriveColor(pct: number): ArcColor {
    if (pct < 70) return "cyan";
    if (pct < 90) return "amber";
    return "violet";
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SystemHealthGauge({
    label,
    pct: pctProp,
    value: valueProp,
    max: maxProp = 100,
    unit = "%",
    color: colorOverride,
}: SystemHealthGaugeProps) {
    // Resolve the canonical percentage for threshold colouring
    let displayValue: number;
    let displayMax: number;

    if (pctProp !== undefined) {
        // Caller supplied a percentage — show it directly on a 0-100 arc
        displayValue = pctProp;
        displayMax   = 100;
    } else {
        // Caller supplied raw value + max
        displayValue = valueProp ?? 0;
        displayMax   = maxProp;
    }

    const normalised = displayMax > 0 ? (displayValue / displayMax) * 100 : 0;
    const color      = colorOverride ?? deriveColor(normalised);

    return (
        <ArcGauge
            value={displayValue}
            max={displayMax}
            label={label}
            unit={unit}
            color={color}
        />
    );
}
