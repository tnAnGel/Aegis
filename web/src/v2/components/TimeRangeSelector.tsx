/**
 * TimeRangeSelector
 *
 * A compact segmented-control for choosing a metrics time window.
 * Styled with V2 design tokens (v2-card, foreground, muted-foreground,
 * ring, border) so it works in both light and dark themes.
 *
 * Usage:
 *   const [range, setRange] = useState<MetricsRange>("1h");
 *   <TimeRangeSelector value={range} onChange={setRange} />
 *
 * Place it top-right of a dashboard section:
 *   <div className="flex items-center justify-between mb-4">
 *     <SectionHeader title="Traffic" />
 *     <TimeRangeSelector value={range} onChange={setRange} />
 *   </div>
 */

import { cn } from "@/lib/cn";
import type { MetricsRange } from "@/types";

// Ordered list of options shown in the segmented control.
const RANGES: { value: MetricsRange; label: string }[] = [
    { value: "1h",  label: "1h"  },
    { value: "6h",  label: "6h"  },
    { value: "24h", label: "24h" },
    { value: "7d",  label: "7d"  },
    { value: "30d", label: "30d" },
];

export interface TimeRangeSelectorProps {
    value: MetricsRange;
    onChange: (range: MetricsRange) => void;
    className?: string;
    /** aria-label for the wrapping group (default: "Time range") */
    label?: string;
}

export function TimeRangeSelector({
    value,
    onChange,
    className,
    label = "Time range",
}: TimeRangeSelectorProps) {
    return (
        <div
            role="group"
            aria-label={label}
            className={cn(
                // Outer wrapper: tight inline flex, V2 card surface, rounded pill
                "inline-flex items-center rounded-md border border-border bg-background",
                "text-xs font-medium text-muted-foreground shadow-sm",
                "divide-x divide-border overflow-hidden",
                className,
            )}
        >
            {RANGES.map(({ value: rv, label: rl }) => {
                const active = rv === value;
                return (
                    <button
                        key={rv}
                        type="button"
                        role="radio"
                        aria-checked={active}
                        onClick={() => onChange(rv)}
                        className={cn(
                            // Base — dense, square-ish segments
                            "relative px-3 py-1 leading-none transition-colors duration-100",
                            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-0",
                            // Active state — filled with primary accent (green) background
                            active
                                ? [
                                    "bg-[var(--v2-accent,#22d362)] text-[#000]",
                                    "font-semibold",
                                ]
                                : [
                                    "hover:bg-muted hover:text-foreground",
                                    "cursor-pointer",
                                ],
                        )}
                    >
                        {rl}
                    </button>
                );
            })}
        </div>
    );
}
