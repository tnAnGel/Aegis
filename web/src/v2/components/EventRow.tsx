import { cn } from "@/lib/cn";
import { SeverityChip, type Severity } from "./SeverityChip";

/**
 * V2 EventRow
 *
 * A single row in the "Security Events — Real-time security events" panel.
 *
 * Layout (left → right):
 *   [SeverityChip]  [title + subtext column]  [age]  [country?]
 *
 * The chip uses the single-letter abbreviation (C/H/M/L).
 * Age and country are right-aligned muted text.
 *
 * Each row has a subtle bottom divider except when `last` is true, or
 * the consumer wraps a list and handles separators externally.
 */
export interface EventRowProps {
    severity: Severity;
    title: string;
    subtext?: string;
    /** Display string for the age, e.g. "2m ago", "just now". */
    age: string;
    /** ISO 3166-1 alpha-2 country code, e.g. "US", "CN". */
    country?: string;
    /** When true, suppress the bottom border. */
    last?: boolean;
    className?: string;
    onClick?: () => void;
}

export function EventRow({
    severity,
    title,
    subtext,
    age,
    country,
    last = false,
    className,
    onClick,
}: EventRowProps) {
    return (
        <div
            role={onClick ? "button" : undefined}
            tabIndex={onClick ? 0 : undefined}
            onClick={onClick}
            onKeyDown={onClick ? (e) => e.key === "Enter" && onClick() : undefined}
            className={cn(
                "flex items-start gap-3 py-3 px-1",
                !last && "border-b border-border",
                onClick && "cursor-pointer rounded-md hover:bg-accent/40 transition-colors",
                className,
            )}
        >
            {/* Severity chip */}
            <div className="mt-0.5 shrink-0">
                <SeverityChip severity={severity} />
            </div>

            {/* Title + subtext */}
            <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground truncate leading-snug">
                    {title}
                </p>
                {subtext && (
                    <p className="text-xs text-muted-foreground truncate mt-0.5 leading-snug">
                        {subtext}
                    </p>
                )}
            </div>

            {/* Age + country */}
            <div className="shrink-0 flex flex-col items-end gap-0.5 ml-2">
                <span className="text-xs text-muted-foreground whitespace-nowrap">{age}</span>
                {country && (
                    <span className="text-[0.65rem] font-mono text-muted-foreground/70 uppercase tracking-widest">
                        {country}
                    </span>
                )}
            </div>
        </div>
    );
}
