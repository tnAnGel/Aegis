import * as React from "react";
import { cn } from "@/lib/cn";
import { SectionHeader } from "./SectionHeader";

/**
 * V2 MetricCard
 *
 * Generic card wrapper that applies the V2 visual chrome:
 *   - rounded-xl via --radius token (set to 0.75rem in tokens.css)
 *   - 1px border-border
 *   - Soft 24px shadow via --v2-card-shadow
 *   - bg-card surface
 *
 * The header row displays:
 *   - A muted small-caps SectionHeader label (left)
 *   - Optional `description` text below the label
 *   - Optional `action` slot (right) — e.g. "View all →" link
 *
 * Children are rendered in a padded content area below the header.
 *
 * Usage:
 *   <MetricCard title="SECURITY EVENTS" action={<a>View all →</a>}>
 *     {rows}
 *   </MetricCard>
 */
export interface MetricCardProps {
    /** Uppercase section header label, e.g. "SECURITY EVENTS" */
    title: string;
    /** Optional subheading / description line beneath the title */
    description?: React.ReactNode;
    /** Optional right-side slot — link, button, badge */
    action?: React.ReactNode;
    /** Card body content */
    children: React.ReactNode;
    className?: string;
    /** Additional className for the inner content wrapper */
    contentClassName?: string;
    /** If true, removes the default content padding so children fill edge-to-edge */
    noPadding?: boolean;
}

export function MetricCard({
    title,
    description,
    action,
    children,
    className,
    contentClassName,
    noPadding = false,
}: MetricCardProps) {
    return (
        <div
            className={cn("v2-card flex flex-col", className)}
            style={{ boxShadow: "var(--v2-card-shadow)" }}
        >
            {/* Header */}
            <div className="flex items-start justify-between px-5 pt-5 pb-3 border-b border-border/50">
                <div className="min-w-0">
                    <SectionHeader label={title} />
                    {description && (
                        <p className="text-xs text-muted-foreground mt-1.5 leading-snug">
                            {description}
                        </p>
                    )}
                </div>
                {action && (
                    <div className="shrink-0 ml-4 mt-0.5 text-xs text-primary font-medium">
                        {action}
                    </div>
                )}
            </div>

            {/* Content */}
            <div
                className={cn(
                    "flex-1 min-h-0",
                    !noPadding && "px-5 py-4",
                    contentClassName,
                )}
            >
                {children}
            </div>
        </div>
    );
}
