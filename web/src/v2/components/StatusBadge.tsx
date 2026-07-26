import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * V2 StatusBadge
 *
 * A small pill indicating operational state. Used in two contexts:
 *   1. Defence Arsenal module status: ACTIVE (green) / STANDBY (muted)
 *   2. System health: Healthy (green) / Degraded (amber) / Error (red)
 *
 * Styled entirely with tokens.css .v2-status-pill-* classes to keep
 * the colour palette in one place. A dot indicator precedes the label.
 */
export type StatusState = "active" | "standby" | "healthy" | "degraded" | "error";

const STATE_META: Record<
    StatusState,
    { label: string; pillClass: string; dotColor: string }
> = {
    active:   { label: "Active",   pillClass: "v2-status-pill-ok",    dotColor: "bg-green-400"  },
    healthy:  { label: "Healthy",  pillClass: "v2-status-pill-ok",    dotColor: "bg-green-400"  },
    standby:  { label: "Standby",  pillClass: "v2-status-pill-warn",  dotColor: "bg-amber-400"  },
    degraded: { label: "Degraded", pillClass: "v2-status-pill-warn",  dotColor: "bg-amber-400"  },
    error:    { label: "Error",    pillClass: "v2-status-pill-error",  dotColor: "bg-red-400"    },
};

export interface StatusBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
    state: StatusState;
    /** Override the displayed text. Defaults to capitalised state name. */
    label?: string;
}

export function StatusBadge({ state, label, className, ...props }: StatusBadgeProps) {
    const meta = STATE_META[state];
    const displayLabel = label ?? meta.label;

    return (
        <span
            className={cn(meta.pillClass, className)}
            aria-label={`Status: ${displayLabel}`}
            {...props}
        >
            {/* Pulsing dot for active/healthy, static for others */}
            <span className="relative inline-flex h-1.5 w-1.5">
                {(state === "active" || state === "healthy") && (
                    <span
                        className={cn(
                            "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
                            meta.dotColor,
                        )}
                    />
                )}
                <span
                    className={cn(
                        "relative inline-flex rounded-full h-1.5 w-1.5",
                        meta.dotColor,
                    )}
                />
            </span>
            {displayLabel}
        </span>
    );
}
