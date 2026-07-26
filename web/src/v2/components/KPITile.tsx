import * as React from "react";
import { cn } from "@/lib/cn";
import { Sparkline } from "@/components/charts/Sparkline";
import type { SeriesPoint } from "@/components/charts/useTimeSeries";

/**
 * V2 KPITile
 *
 * Top-row KPI card as shown in the dashboard mockup:
 *
 *   ┌────────────────────────────────┐
 *   │  LABEL               [icon?]  │
 *   │  BIG VALUE                    │
 *   │  ↑ +12.3%  vs yesterday       │
 *   │  ▁▃▅▄▆▇▅▃ (sparkline)         │
 *   └────────────────────────────────┘
 *
 * Props:
 *   label          — uppercase muted section label, e.g. "TOTAL REQUESTS"
 *   value          — formatted value string, e.g. "1.24M", "98.7%", "3"
 *   delta          — optional percent-change string, e.g. "+12.3%" or "-4.1%"
 *   deltaDirection — "up" | "down" | "neutral" — determines arrow and colour
 *   deltaLabel     — label beside the delta, defaults to "vs yesterday"
 *   sparklineData  — SeriesPoint[] from useTimeSeries / useTimeSeriesMulti
 *   sparklineColor — hex color for the sparkline. Defaults to primary green.
 *   icon           — optional React node for the top-right icon slot
 *   valueColor     — optional Tailwind/inline color class to tint the big number
 *                    (e.g. "text-destructive" for red Threat Score)
 *
 * The component intentionally has NO data-fetching logic — it is a pure
 * presentational primitive. Pages supply pre-derived props.
 */

export type DeltaDirection = "up" | "down" | "neutral";

export interface KPITileProps {
    label: string;
    value: string | number;
    delta?: string;
    deltaDirection?: DeltaDirection;
    deltaLabel?: string;
    sparklineData?: SeriesPoint[];
    sparklineColor?: string;
    icon?: React.ReactNode;
    /** Tailwind class(es) to apply to the big value, e.g. "text-destructive" */
    valueColor?: string;
    className?: string;
}

// Arrow glyphs for delta direction
const ARROW: Record<DeltaDirection, string> = {
    up:      "↑",
    down:    "↓",
    neutral: "→",
};

// Tailwind colour classes for the delta text
const DELTA_COLOR: Record<DeltaDirection, string> = {
    up:      "text-green-400",
    down:    "text-destructive",
    neutral: "text-muted-foreground",
};

export function KPITile({
    label,
    value,
    delta,
    deltaDirection = "neutral",
    deltaLabel = "vs yesterday",
    sparklineData,
    sparklineColor = "#22d362",
    icon,
    valueColor,
    className,
}: KPITileProps) {
    const hasDelta = delta !== undefined && delta !== null;
    const hasSparkline = Array.isArray(sparklineData) && sparklineData.length >= 2;

    return (
        <div
            className={cn("v2-card flex flex-col px-5 pt-5 pb-4 gap-2", className)}
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Top row: label + optional icon */}
            <div className="flex items-center justify-between gap-2">
                <p className="v2-section-label truncate">{label}</p>
                {icon && (
                    <span className="shrink-0 text-muted-foreground/60 text-base leading-none">
                        {icon}
                    </span>
                )}
            </div>

            {/* Big value */}
            <p
                className={cn(
                    "v2-kpi-number text-3xl font-bold leading-none tracking-tight text-foreground",
                    valueColor,
                )}
                aria-label={`${label}: ${value}`}
            >
                {value}
            </p>

            {/* Delta row */}
            {hasDelta && (
                <div className="flex items-center gap-1.5">
                    <span
                        className={cn(
                            "text-xs font-semibold tabular-nums",
                            DELTA_COLOR[deltaDirection],
                        )}
                        aria-label={`Change: ${delta}`}
                    >
                        {ARROW[deltaDirection]}&thinsp;{delta}
                    </span>
                    <span className="text-xs text-muted-foreground/70">{deltaLabel}</span>
                </div>
            )}

            {/* Sparkline — pushed to the bottom of the card */}
            {hasSparkline && (
                <div className="mt-auto pt-1">
                    <Sparkline
                        data={sparklineData!}
                        color={sparklineColor}
                        height={36}
                    />
                </div>
            )}

            {/* Placeholder height when no sparkline so all tiles align */}
            {!hasSparkline && <div className="mt-auto pt-1" style={{ height: 36 }} aria-hidden />}
        </div>
    );
}
