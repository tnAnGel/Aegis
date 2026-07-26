import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * V2 SeverityChip
 *
 * A small, uppercase filled rounded chip indicating event severity.
 * Uses the .v2-chip-* CSS classes defined in tokens.css which apply
 * a 20%-opacity background, 40%-opacity border and full-saturation
 * text from the V2 severity palette:
 *
 *   CRITICAL → red   (--v2-severity-critical)
 *   HIGH     → amber (--v2-severity-high)
 *   MEDIUM   → yellow (--v2-severity-medium)
 *   LOW      → sky   (--v2-severity-low)
 *
 * Renders a single-letter abbreviation inside a square-ish chip,
 * matching the "C / H / M / L" treatment in the mockup's event list.
 */
export type Severity = "critical" | "high" | "medium" | "low";

const SEVERITY_META: Record<Severity, { label: string; abbrev: string }> = {
    critical: { label: "Critical", abbrev: "C" },
    high:     { label: "High",     abbrev: "H" },
    medium:   { label: "Medium",   abbrev: "M" },
    low:      { label: "Low",      abbrev: "L" },
};

export interface SeverityChipProps extends React.HTMLAttributes<HTMLSpanElement> {
    severity: Severity;
    /** Override displayed text. Defaults to single-letter abbreviation. */
    showLabel?: boolean;
}

export function SeverityChip({ severity, showLabel = false, className, ...props }: SeverityChipProps) {
    const meta = SEVERITY_META[severity];
    return (
        <span
            className={cn(
                "inline-flex items-center justify-center rounded font-mono font-semibold uppercase",
                // square-ish chip sizing
                showLabel
                    ? "px-2 py-0.5 text-[0.65rem] tracking-wider"
                    : "w-5 h-5 text-[0.6rem]",
                `v2-chip-${severity}`,
                className,
            )}
            title={meta.label}
            aria-label={`Severity: ${meta.label}`}
            {...props}
        >
            {showLabel ? meta.label : meta.abbrev}
        </span>
    );
}
